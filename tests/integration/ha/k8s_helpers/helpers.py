# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""High availability helpers."""

import os
import re
import string
import subprocess
import tarfile
import tempfile
from datetime import datetime
from logging import getLogger

import urllib3
from kubernetes import client, config, stream
from kubernetes.client.rest import ApiException
from tenacity import (
    Retrying,
    stop_after_delay,
    wait_fixed,
)

from tests.integration.helpers import NO_TTY_STDIN, get_application_unit_ids

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
                ["sudo", "k8s", "kubectl", "apply", "-f", temp_file.name],
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
    delete_cmd = (
        f"sudo k8s kubectl -n {model_name} delete networkchaos network-loss-primary "
        f"--ignore-not-found --wait=false"
    )
    try:
        subprocess.check_output(delete_cmd, shell=True, env=env, stderr=subprocess.STDOUT)
    except subprocess.CalledProcessError as err:
        logger.warning(
            "Failed to delete networkchaos (will force-clear finalizers): %s",
            err.output,
        )

    patch_cmd = (
        f"sudo k8s kubectl -n {model_name} patch networkchaos network-loss-primary "
        f'--type=merge -p \'{{"metadata":{{"finalizers":[]}}}}\''
    )
    try:
        subprocess.check_output(patch_cmd, shell=True, env=env, stderr=subprocess.STDOUT)
    except subprocess.CalledProcessError as err:
        if b"NotFound" not in (err.output or b"") and err.returncode != 1:
            logger.warning("Failed to patch networkchaos finalizers: %s", err.output)


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


def k8s_is_unit_reachable(
    model_name: str,
    source_unit: str,
    to_host: str,
    port: int = 9200,
    timeout: float = 2.0,
) -> bool:
    """Test TCP reachability to a unit FQDN:port from a peer unit via juju ssh + python.

    Uses the charm container (default juju ssh target), which shares the pod network
    namespace with the workload. Avoids ephemeral probe pods and juju ssh -c quoting issues
    by feeding the Python script on stdin.
    """
    script = (
        "import socket, sys\n"
        "try:\n"
        f"    socket.create_connection(({to_host!r}, {port}), {timeout})\n"
        "except OSError as exc:\n"
        "    print(exc, file=sys.stderr)\n"
        "    sys.exit(1)\n"
    )
    logger.info(
        "Checking reachability from %s to %s:%s (model=%s)",
        source_unit,
        to_host,
        port,
        model_name,
    )
    result = subprocess.run(
        ["juju", "ssh", f"--model={model_name}", source_unit, "python3"],
        input=script,
        capture_output=True,
        text=True,
        env={**os.environ, "JUJU_MODEL": model_name},
        check=False,
    )
    is_reachable = result.returncode == 0
    if is_reachable:
        logger.info("Success: %s is reachable from %s.", to_host, source_unit)
    else:
        logger.info(
            "Failure: %s is NOT reachable from %s (rc=%s stderr=%s stdout=%s)",
            to_host,
            source_unit,
            result.returncode,
            result.stderr.strip(),
            result.stdout.strip(),
        )
    return is_reachable


def _remote_exit_code_from_error(error: subprocess.CalledProcessError) -> int:
    """Return Juju's wrapped remote exit code when present, otherwise local returncode."""
    output = "\n".join(
        str(stream) for stream in (error.stderr, error.output, error.stdout) if stream is not None
    )
    match = re.search(r"exit code (?P<exit_code>\d+)", output)
    if match:
        return int(match.group("exit_code"))
    return error.returncode


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
    assert response.returncode == 0, (
        f"Failed to add to pebble layer, unit={unit_name}, container={container_name}, service={service_name}"
    )

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
                assert response.returncode == 0, (
                    f"Failed to replan pebble layer, unit={unit_name}, container={container_name}, service={service_name}"
                )

    # pebble replan restarts the service; wait until opensearch is back up on port 9200
    for attempt in Retrying(stop=stop_after_delay(120), wait=wait_fixed(3)):
        with attempt:
            result = subprocess.run(
                f"juju ssh --container opensearch {unit_name} lsof -ti:9200".split(),
                capture_output=True,
                text=True,
                stdin=subprocess.DEVNULL,
                env={**os.environ, "JUJU_MODEL": model_name},
            )
            assert result.stdout.strip(), (
                f"opensearch not yet listening on port 9200 on {unit_name}"
            )


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
        return_code, opensearch_pid, stderr = await ops_test.juju(
            *get_pid_cmd, check=False, stdin=NO_TTY_STDIN
        )
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
