# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""High availability helpers."""

import os
import re
import string
import subprocess
import tarfile
import tempfile
import time
from datetime import datetime
from logging import getLogger

import urllib3
from kubernetes import client, config, stream
from kubernetes.client.rest import ApiException
from tenacity import (
    Retrying,
    stop_after_attempt,
    stop_after_delay,
    wait_fixed,
)

from tests.integration.helpers import get_application_unit_ids

logger = getLogger(__name__)

VM_RESTART_DELAY_DEFAULT = 20
K8S_RESTART_DELAY_DEFAULT = 5
RESTART_DELAY_PATCHED = 120
OPENSEARCH_PROCESS_PATTERN = r"java.*org\.opensearch\.bootstrap\.OpenSearch"


EXTEND_PEBBLE_RESTART_DELAY_YAML = """services:
  opensearch:
    override: merge
    backoff-delay: {delay}s
    backoff-limit: {delay}s
"""

RESTORE_PEBBLE_RESTART_DELAY_YAML = """services:
  opensearch:
    override: merge
    backoff-delay: 500ms
    backoff-limit: 30s
"""


def k8s_cut_network_from_unit_without_ip_change(model_name: str, machine_name: str) -> None:
    """Cut network from a k8s pod without causing the change of the unit IP address."""
    # Apply a NetworkChaos file to use chaos-mesh to simulate a network cut.
    with tempfile.NamedTemporaryFile(dir=".") as temp_file:
        # Generates a manifest for chaosmesh to simulate network failure for a pod
        with open(
            "tests/integration/ha/k8s_helpers/chaos_network_loss.yml"
        ) as chaos_network_loss_file:
            logger.info(
                f"Calling network loss on ns={model_name} and pod={machine_name.replace('/', '-')}"
            )
            template = string.Template(chaos_network_loss_file.read())
            chaos_network_loss = template.substitute(
                namespace=model_name,
                pod=machine_name.replace("/", "-"),
            )

            temp_file.write(str.encode(chaos_network_loss))
            temp_file.flush()

        # Apply the generated manifest, chaosmesh would then make the pod inaccessible
        env = os.environ
        env["KUBECONFIG"] = os.path.expanduser("~/.kube/config")
        try:
            command_result = subprocess.check_output(
                ["microk8s", "kubectl", "apply", "-f", temp_file.name],
                env=env,
                stderr=subprocess.STDOUT,
            )
        except subprocess.CalledProcessError as err:
            logger.error(
                f"Failed to apply network isolation: [{err.returncode}] {err.stderr=}, {err.stdout=}"
            )
            raise
        logger.info("Result of isolating unit from cluster is '%s'", command_result)


def k8s_restore_network_to_unit(model_name: str) -> None:
    """Restore network from a lxc container.

    Args:
        model_name: The juju model name to delete the network cut from
    """
    env = os.environ
    env["KUBECONFIG"] = os.path.expanduser("~/.kube/config")
    subprocess.check_output(
        f"microk8s kubectl -n {model_name} delete networkchaos network-loss-primary",
        shell=True,
        env=env,
    )


def deploy_chaos_mesh(namespace: str) -> None:
    """Deploy chaos mesh to the provided namespace.

    Chaos mesh can them be used by the tests to simulate a variety of failures.

    Args:
        namespace: The namespace to deploy chaos mesh to
    """
    env = os.environ
    env["KUBECONFIG"] = os.path.expanduser("~/.kube/config")

    subprocess.check_output(
        f"tests/integration/ha/k8s_helpers/deploy_chaos_mesh.sh {namespace}",
        shell=True,
        env=env,
    )


def destroy_chaos_mesh(namespace: str) -> None:
    """Destroy chaos mesh on a provided namespace.

    Cleans up the test K8S from test related dependencies.

    Args:
        namespace: The namespace to deploy chaos mesh to
    """
    env = os.environ
    env["KUBECONFIG"] = os.path.expanduser("~/.kube/config")

    subprocess.check_output(
        f"tests/integration/ha/k8s_helpers/destroy_chaos_mesh.sh {namespace}",
        shell=True,
        env=env,
    )


def k8s_is_unit_reachable(namespace: str, source_pod_name: str, to_host: str) -> bool:
    """Test network reachability to a unit in k8s from a temporary pod."""
    # ---------------------------------------------------------
    # 1. Setup Client and Bypass SSL (for local/testing clusters)
    # ---------------------------------------------------------
    config.load_kube_config()

    configuration = client.Configuration.get_default_copy()
    configuration.verify_ssl = False
    client.Configuration.set_default(configuration)
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    v1 = client.CoreV1Api()

    # ---------------------------------------------------------
    # 2. Fetch Labels from the Source Pod
    # ---------------------------------------------------------
    try:
        source_pod = v1.read_namespaced_pod(name=source_pod_name, namespace=namespace)
        source_labels = source_pod.metadata.labels or {}
        logger.info(f"Fetched labels from {source_pod_name}: {source_labels}")
    except ApiException as e:
        logger.error(f"Failed to read source pod {source_pod_name}: {e}")
        return False

    # ---------------------------------------------------------
    # 3. Define the Temporary Test Pod
    # ---------------------------------------------------------
    temp_pod_name = f"netshoot-test-{int(time.time())}"

    pod_manifest = client.V1Pod(
        metadata=client.V1ObjectMeta(
            name=temp_pod_name,
            namespace=namespace,
            labels=source_labels,  # <--- Injecting the source pod's labels here
        ),
        spec=client.V1PodSpec(
            restart_policy="Never",
            containers=[
                client.V1Container(
                    name="netshoot",
                    image="nicolaka/netshoot",
                    # Ping five times (-c 5), wait up to 2 seconds for a response (-W 2)
                    command=["ping", "-c", "5", "-W", "2", to_host],
                )
            ],
        ),
    )

    # ---------------------------------------------------------
    # 4. Execute and Wait for Results
    # ---------------------------------------------------------
    try:
        logger.info(f"Creating test pod '{temp_pod_name}' to ping {to_host}...")
        v1.create_namespaced_pod(namespace=namespace, body=pod_manifest)

        # Poll the pod status until it completes
        phase = None
        for attempt in Retrying(stop=stop_after_attempt(30), wait=wait_fixed(2), reraise=True):
            with attempt:
                pod_status = v1.read_namespaced_pod(name=temp_pod_name, namespace=namespace)
                phase = pod_status.status.phase

                if phase not in ["Succeeded", "Failed"]:
                    logger.info(
                        f"Pod '{temp_pod_name}' is in phase '{phase}'. Waiting for completion..."
                    )
                    raise ValueError("Pod not completed yet")

        # Optional: Fetch the actual ping output logs for debugging
        logs = v1.read_namespaced_pod_log(name=temp_pod_name, namespace=namespace)
        logger.info(f"Ping Output:\n{logs.strip()}")

        # If phase is Succeeded, the ping command returned exit code 0
        is_reachable = phase == "Succeeded"

        if is_reachable:
            logger.info(f"Success: {to_host} is reachable from {source_pod_name}.")
        else:
            logger.error(f"Failure: {to_host} is NOT reachable from {source_pod_name}.")

        return is_reachable

    except ApiException as e:
        logger.error(f"Exception during pod creation/execution: {e}")
        return False

    finally:
        logger.info(f"Cleaning up pod '{temp_pod_name}'...")
        try:
            v1.delete_namespaced_pod(name=temp_pod_name, namespace=namespace)
            logger.info(f"Pod '{temp_pod_name}' deleted successfully.")
        except ApiException as e:
            logger.error(f"Failed to delete temporary pod {temp_pod_name}: {e}")


def _remote_exit_code_from_error(error: subprocess.CalledProcessError) -> int:
    """Return Juju's wrapped remote exit code when present, otherwise local returncode."""
    output = "\n".join(
        str(stream) for stream in (error.stderr, error.output, error.stdout) if stream is not None
    )
    match = re.search(r"exit code (?P<exit_code>\d+)", output)
    if match:
        return int(match.group("exit_code"))
    return error.returncode


def k8s_send_process_control_signal(
    unit_name: str,
    model_full_name: str,
    signal: str,
    db_process: str = OPENSEARCH_PROCESS_PATTERN,
) -> None:
    """Send control signal to a database process running on a Juju unit.

    Args:
        unit_name: the Juju unit running the process
        model_full_name: the Juju model for the unit
        signal: the signal to issue, e.g., `SIGKILL`, `SIGTERM`, `SIGSTOP`, `SIGCONT`
        db_process: the path to the database process binary
    """
    normalized_signal = signal.upper()
    command = [
        "juju",
        "ssh",
        "--container",
        "opensearch",
        unit_name,
        "pkill",
        "--signal",
        normalized_signal,
        "-f",
        db_process,
    ]
    env = {**os.environ, "JUJU_MODEL": model_full_name}

    try:
        subprocess.check_output(
            command, env=env, stderr=subprocess.PIPE, universal_newlines=True, timeout=5
        )
        # For SIGSTOP and SIGCONT, check_output should succeed cleanly and reach here.
        logger.info(
            "Signal %s successfully sent to database process on unit %s.",
            normalized_signal,
            unit_name,
        )

    except subprocess.CalledProcessError as e:
        # Exit code 137 = SIGKILL container death
        # Exit code 143 = SIGTERM container death
        # Exit code 255 = SSH disconnect caused by sudden container termination
        termination_signals = ["SIGKILL", "SIGTERM"]
        expected_exit_codes = (137, 143, 255)
        exit_code = _remote_exit_code_from_error(e)

        if normalized_signal in termination_signals and exit_code in expected_exit_codes:
            logger.info(
                "Process terminated successfully via %s (received expected exit code %s).",
                normalized_signal,
                exit_code,
            )
        else:
            logger.error(
                "Failed to send signal %s to process %s on unit %s",
                normalized_signal,
                db_process,
                unit_name,
            )
            logger.error("Error details: return code %s, stderr: %s", e.returncode, e.stderr)
            raise

    except subprocess.TimeoutExpired as e:
        if normalized_signal == "SIGSTOP":
            logger.info(
                "Signal %s likely reached process %s on unit %s; Juju exec timed out after "
                "the process stopped.",
                normalized_signal,
                db_process,
                unit_name,
            )
        else:
            logger.error(
                "Timeout while sending signal %s to process %s on unit %s",
                normalized_signal,
                db_process,
                unit_name,
            )
            logger.error("Error details: %s", e)
            raise

    time.sleep(3)  # give some time for the signal to take effect before the test continues


def pebble_patch_restart_delay(
    model_name: str,
    unit_name: str,
    delay: int | None = None,
    ensure_replan: bool = False,
) -> None:
    """Modify the pebble restart delay of the underlying process.

    Args:
        model_name: The Juju model name for the unit
        unit_name: The name of unit to extend the pebble restart delay for
        delay: The new restart delay to apply
        ensure_replan: Whether to check that the replan command succeeded
    """
    pebble_file_content = (
        EXTEND_PEBBLE_RESTART_DELAY_YAML.format(delay=delay)
        if delay
        else RESTORE_PEBBLE_RESTART_DELAY_YAML
    )
    config.load_kube_config()

    configuration = client.Configuration.get_default_copy()
    configuration.verify_ssl = False
    client.Configuration.set_default(configuration)
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    kube_client = client.CoreV1Api()

    pod_name = unit_name.replace("/", "-")
    container_name = "opensearch"
    service_name = "opensearch"
    now = datetime.now().isoformat()

    with tempfile.NamedTemporaryFile() as pebble_plan_file:
        pebble_plan_file.write(str.encode(pebble_file_content))
        pebble_plan_file.flush()

        copy_file_into_pod(
            kube_client,
            model_name,
            pod_name,
            container_name,
            pebble_plan_file.name,
            f"/tmp/pebble_plan_{now}.yml",
        )

    add_to_pebble_layer_commands = (
        f"/charm/bin/pebble add --combine {service_name} /tmp/pebble_plan_{now}.yml"
    )
    response = stream.stream(
        kube_client.connect_get_namespaced_pod_exec,
        pod_name,
        model_name,
        container=container_name,
        command=add_to_pebble_layer_commands.split(),
        stdin=False,
        stdout=True,
        stderr=True,
        tty=False,
        _preload_content=False,
    )
    response.run_forever(timeout=5)
    assert (
        response.returncode == 0
    ), f"Failed to add to pebble layer, unit={unit_name}, container={container_name}, service={service_name}"

    for attempt in Retrying(stop=stop_after_delay(60), wait=wait_fixed(3)):
        with attempt:
            replan_pebble_layer_commands = "/charm/bin/pebble replan"
            response = stream.stream(
                kube_client.connect_get_namespaced_pod_exec,
                pod_name,
                model_name,
                container=container_name,
                command=replan_pebble_layer_commands.split(),
                stdin=False,
                stdout=True,
                stderr=True,
                tty=False,
                _preload_content=False,
            )
            response.run_forever(timeout=60)
            if ensure_replan:
                assert (
                    response.returncode == 0
                ), f"Failed to replan pebble layer, unit={unit_name}, container={container_name}, service={service_name}"


def copy_file_into_pod(
    client: client.api.core_v1_api.CoreV1Api,
    namespace: str,
    pod_name: str,
    container_name: str,
    source_path: str,
    destination_path: str,
) -> None:
    """Copy file contents into pod.

    Args:
        client: The kubernetes CoreV1Api client
        namespace: The namespace of the pod to copy files to
        pod_name: The name of the pod to copy files to
        container_name: The name of the pod container to copy files to
        source_path: The path of the file to copy from the local machine
        destination_path: The path to copy the file to in the pod
    """
    exec_command = ["tar", "xvf", "-", "-C", "/"]

    api_response = stream.stream(
        client.connect_get_namespaced_pod_exec,
        pod_name,
        namespace,
        container=container_name,
        command=exec_command,
        stdin=True,
        stdout=True,
        stderr=True,
        tty=False,
        _preload_content=False,
    )

    with tempfile.TemporaryFile() as tar_buffer:
        with tarfile.open(fileobj=tar_buffer, mode="w") as tar:
            tar.add(source_path, destination_path)

        tar_buffer.seek(0)
        commands = []
        commands.append(tar_buffer.read())

        while api_response.is_open():
            api_response.update(timeout=1)

            if commands:
                command = commands.pop(0)
                api_response.write_stdin(command.decode())
            else:
                break

        api_response.close()


# def patch_restart_delay(
#     juju: jubilant.Juju, unit_name: str, delay: int | None, substrate: Substrate
# ) -> None:
#     """Update the restart delay for the database process based on the substrate."""
#     match substrate:
#         case Substrate.VM:
#             lxd_patch_restart_delay(juju, unit_name, delay)
#         case Substrate.K8S:
#             pebble_patch_restart_delay(juju, unit_name, delay=delay, ensure_replan=True)


# def reboot_unit(juju: jubilant.Juju, unit_name: str, substrate: Substrate) -> None:
#     """Reboot a unit."""
#     if substrate == Substrate.VM:
#         juju.exec(command="sudo reboot", unit=unit_name)
#     else:
#         delete_pod(unit_name.replace("/", "-"), juju.model)


def delete_pod(pod_name: str, namespace="testing") -> None:
    """Delete a pod from the cluster."""
    # Load the kubeconfig file from your local machine (~/.kube/config)
    # Note: If running this script INSIDE a pod, use config.load_incluster_config() instead.
    config.load_kube_config()

    configuration = client.Configuration.get_default_copy()
    configuration.verify_ssl = False
    client.Configuration.set_default(configuration)
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    # CoreV1Api contains the methods for core resources like Pods, Services, etc.
    v1 = client.CoreV1Api()

    try:
        # Call the API to delete the pod
        logger.info("Attempting to delete pod %s in namespace '%s'...", pod_name, namespace)
        v1.delete_namespaced_pod(name=pod_name, namespace=namespace)

        logger.info("Success! Pod deleted.")

    except ApiException as e:
        # Handle API errors (e.g., pod not found, unauthorized, etc.)
        if e.status == 404:
            logger.warning("Error: Pod '%s' not found in namespace '%s'.", pod_name, namespace)
        else:
            logger.error("Exception when calling CoreV1Api->delete_namespaced_pod: %s", e)


def instance_ip(model: str, instance: str) -> str:
    """Translate juju instance name to IP.

    Args:
        model: The name of the model
        instance: The name of the instance

    Returns:
        The (str) IP address of the instance
    """
    output = subprocess.check_output(f"juju machines --model {model}".split())

    for line in output.decode("utf8").splitlines():
        if instance in line:
            return line.split()[2]

    return ""


async def k8s_all_processes_down(
    ops_test, app: str, db_process: str = OPENSEARCH_PROCESS_PATTERN
) -> bool:
    """Check if the OpenSearch process is down on every k8s unit."""
    for unit_id in get_application_unit_ids(ops_test, app):
        unit_name = f"{app}/{unit_id}"
        get_pid_cmd = [
            "ssh",
            "--container",
            "opensearch",
            unit_name,
            "pgrep",
            "-f",
            db_process,
        ]
        return_code, opensearch_pid, stderr = await ops_test.juju(*get_pid_cmd, check=False)
        if return_code not in (0, 1):
            logger.error(
                "Failed to check OpenSearch process on unit %s: rc=%s, stderr=%s",
                unit_name,
                return_code,
                stderr,
            )
            return False
        if opensearch_pid.strip():
            return False

    return True
