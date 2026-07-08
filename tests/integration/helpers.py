#!/usr/bin/env python3
# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

import asyncio
import base64
import json
import logging
import random
import shlex
import socket
import subprocess
import tempfile
from collections.abc import Callable
from datetime import datetime, timedelta
from hashlib import md5
from types import SimpleNamespace
from typing import Any, Dict, List, Optional, Union
from urllib.parse import urlparse
from uuid import uuid4

import jubilant
import requests
import yaml
from data_platform_helpers.advanced_statuses import StatusObject
from opensearchpy import OpenSearch
from tenacity import (
    RetryError,
    Retrying,
    retry,
    stop_after_attempt,
    stop_after_delay,
    wait_fixed,
    wait_random,
)

from tests.helpers import Substrate

from .conftest import APP_NAME, CLIENT_CHARM
from .models import Status, Unit

logging.basicConfig(
    format="%(asctime)s - %(levelname)s - %(filename)s:%(lineno)s", datefmt="%H:%M:%S"
)
logger = logging.getLogger(__name__)


# Keep the existing connect/read timeout used by http_request.
_HTTP_REQUEST_TIMEOUT = (17, 17)
EmptyBlockedStatus = StatusObject(
    status="blocked",
    message="",
)
CosBlockedStatus = StatusObject(
    status="blocked",
    message="Missing ['grafana-cloud-config']|['grafana-dashboards-provider']|['logging-consumer']|['send-remote-write'] for cos-agent",
)
EmptyActiveStatus = StatusObject(
    status="active",
    message="",
)
EmptyMaintenanceStatus = StatusObject(
    status="maintenance",
    message="",
)

# Cache of model name -> model uuid to avoid repeated `juju show-model` calls.
_MODEL_UUID_CACHE: Dict[str, str] = {}


def _model_name(juju: jubilant.Juju) -> str:
    """Return the active Juju model name."""
    return juju.model or juju.status().model.name


def _model_uuid(juju: jubilant.Juju) -> str:
    """Return the active Juju model uuid (cached)."""
    name = _model_name(juju)
    if name not in _MODEL_UUID_CACHE:
        _MODEL_UUID_CACHE[name] = juju.show_model(name).model_uuid
    return _MODEL_UUID_CACHE[name]


def _is_k8s(juju: jubilant.Juju) -> bool:
    """Return whether the current model runs on a Kubernetes (CAAS) substrate."""
    return juju.status().model.type == "caas"


def get_raw_application(juju: jubilant.Juju, app: str) -> Dict[str, Any]:
    """Get raw application details."""
    return json.loads(
        subprocess.check_output(
            f"juju status --model {_model_name(juju)} {app} --format=json".split()
        )
    )["applications"][app]


def _get_unit_address(raw_unit: dict[str, Any]) -> Optional[str]:
    """Return unit address from raw status; K8s may use 'address' instead of 'public-address'."""
    return raw_unit.get("public-address") or raw_unit.get("address")


async def deploy_opensearch(  # noqa: C901
    juju: jubilant.Juju,
    charm: str,
    substrate: str,
    application_name: str,
    num_units: int,
    *,
    series: Optional[str] = None,
    config: Optional[Dict[str, Any]] = None,
    constraints: Optional[Dict[str, Any]] = None,
    resources: Optional[Dict[str, str]] = None,
    storage: Optional[Dict[str, Any]] = None,
) -> None:
    """Deploy the OpenSearch charm."""
    deploy_kwargs: Dict[str, Any] = {
        "app": application_name,
        "num_units": num_units,
    }
    # Juju does not use `series`/`base` for K8s applications.
    if series and substrate != "k8s":
        deploy_kwargs["base"] = _series_to_base(series)
    if config:
        deploy_kwargs["config"] = config
    if constraints:
        deploy_kwargs["constraints"] = constraints
    if resources:
        deploy_kwargs["resources"] = resources
    if storage:
        deploy_kwargs["storage"] = storage

    juju.deploy(charm, **deploy_kwargs)


def _series_to_base(series: str) -> str:
    """Convert a legacy series name to a Juju base string."""
    mapping = {
        "jammy": "ubuntu@22.04",
        "noble": "ubuntu@24.04",
    }
    return mapping.get(series, series)


async def get_cloud_type(juju: jubilant.Juju) -> str:
    """Return current cloud type of the selected controller."""
    return juju.status().model.cloud


def now() -> str:
    """Print date."""
    return datetime.now().strftime("%H:%M:%S")


def _dump_juju_logs(model: str, unit: Optional[str] = None, lines: int = 500) -> None:
    """Dump juju logs on the console."""
    target_file = f"/tmp/{uuid4().hex}.txt"

    cmd = "juju debug-log"
    if unit:
        pos = unit.rfind("-")
        if pos != -1:
            unit = f"{unit[:pos]}/{unit[pos + 1 :]}"  # noqa
        cmd = f"{cmd} --include={unit}"

    cmd = f"{cmd} --model={model} --limit {lines} > {target_file}; cat {target_file}"
    logger.error("Dumping juju logs for %s:", unit if unit else "all")
    logger.error(subprocess.check_output(cmd, shell=True).decode("utf-8"))
    logger.error("\n\n")


def _progress_line(units: List[Unit]) -> str:
    """Log progress line."""
    log = ""
    for u in units:
        if not log:
            log = (
                f"\n\tapp: {u.short_name.split('-')[0]} {u.app_status.value} -- "
                f"message: {u.app_status.message}\n"
            )

        log = (
            f"{log}\t\t{u.name}{'*' if u.is_leader else ' '} -- ({u.ip}) -- [{u.agent_status.value} "
            f"(since: {u.agent_status.since.strftime('%H:%M:%S')})] "
            f"{u.workload_status.value}: {u.workload_status.message or ''}\n"
        )

    return log


async def get_unit_hostname(juju: jubilant.Juju, unit_id: int, app: str) -> str:
    """Get the hostname of a specific unit."""
    return juju.ssh(f"{app}/{unit_id}", "hostname").strip()


async def _get_unit(
    juju: jubilant.Juju,
    app: str,
    raw_app: dict[str, Any],
    unit_name: str,
    raw_unit: dict[str, Any],
    subordinate: bool = False,
) -> Unit:
    """Create a Unit object from raw unit data."""
    unit_id = int(unit_name.split("/")[-1])

    app_id = f"{_model_uuid(juju)}/{app}"
    app_short_id = md5(app_id.encode()).hexdigest()[:3]
    # K8s units may not have "machine" or use a different structure; use -1 when missing.
    machine_val = raw_unit.get("machine", -1)
    machine_id = -1 if subordinate else (int(machine_val) if machine_val != -1 else -1)

    ip = _get_unit_address(raw_unit) or ""

    try:
        hostname = await get_unit_hostname(juju, unit_id, app)
    except Exception:
        # On K8s use address as hostname for wait logic.
        hostname = ip

    return Unit(
        id=unit_id,
        short_name=unit_name.replace("/", "-"),
        name=f"{unit_name.replace('/', '-')}.{app_short_id}",
        ip=ip,
        hostname=hostname,
        is_leader=raw_unit.get("leader", False),
        machine_id=machine_id,
        workload_status=Status(
            value=raw_unit["workload-status"]["current"],
            since=raw_unit["workload-status"]["since"],
            message=raw_unit["workload-status"].get("message"),
        ),
        agent_status=Status(
            value=raw_unit["juju-status"]["current"],
            since=raw_unit["juju-status"]["since"],
        ),
        app_status=Status(
            value=raw_app["application-status"]["current"],
            since=raw_app["application-status"]["since"],
            message=raw_app["application-status"].get("message"),
        ),
    )


async def get_application_units(juju: jubilant.Juju, app: str) -> List[Unit]:
    """Get fully detailed units of an application."""
    status = json.loads(
        subprocess.check_output(f"juju status --model {_model_name(juju)} --format=json".split())
    )["applications"]
    if app not in status:
        return []
    raw_app = get_raw_application(juju, app)
    units = []
    for u_name, raw_unit in raw_app.get("units", {}).items():
        if not _get_unit_address(raw_unit):
            # unit not ready yet...
            continue
        units.append(_get_unit(juju, app, raw_app, u_name, raw_unit))

    return await asyncio.gather(*units) if units else []


async def get_application_subordinate_units(
    juju: jubilant.Juju, principal_app: str, app: str
) -> List[Unit]:
    """Get fully detailed units of an application."""
    raw_app = get_raw_application(juju, app)
    units = []
    for principal_unit in get_raw_application(juju, principal_app)["units"].values():
        u_name, raw_unit = None, None
        for u_name, raw_unit in principal_unit["subordinates"].items():
            if u_name.startswith(f"{app}/"):
                break
        else:
            raise ValueError(f"Subordinate unit for {app} not found in {principal_app}")

        if not _get_unit_address(raw_unit):
            # unit not ready yet...
            continue

        units.append(_get_unit(juju, app, raw_app, u_name, raw_unit, subordinate=True))
    return await asyncio.gather(*units) if units else []


def _check_status(status: Status, check: StatusObject) -> bool:
    """Check if charm status is the same as from the advanced status lib checked status.

    Interpolated statuses are handled through regex.

    Args:
        status: charm status.
        check: original status from advanced status lib.

    Returns:
        whether charm status corresponding to the checked status.
    """
    if status.value != check.status.lower():
        return False

    if not status.message and not check.message:
        return True

    return bool(status.message) and (
        status.message == check.message
        or status.message.startswith(check.message)
        or status.message.startswith(f"{check.message:.40}")
        or (check.short_message is not None and check.short_message in status.message)
    )


def _is_every_condition_on_app_met(
    juju: jubilant.Juju,
    app: str,
    units: list[Unit] | None,
    app_statuses: list[StatusObject] | None,
) -> bool:
    """Evaluate if all the conditions of an application are met."""
    if units:
        current_status = units[0].app_status
    else:
        current_status = get_raw_application(juju, app)["application-status"]
        current_status = Status(
            value=current_status["current"],
            since=current_status["since"],
            message=current_status.get("message"),
        )

    if app_statuses:
        return any(_check_status(current_status, status) for status in app_statuses)

    return current_status.value == "active"


def _is_every_condition_on_units_met(
    model: str,
    units: list[Unit],
    unit_statuses: list[StatusObject] | None,
    idle_period: int,
) -> bool:
    """Evaluate if all the conditions of a unit are met."""
    for unit in units:
        if unit.agent_status.value != "idle":
            return False

        if unit.workload_status.value == "error":
            logger.error(f"Error in: {unit.name}")
            _dump_juju_logs(model, unit.name)

        if unit_statuses and not any(
            _check_status(unit.workload_status, status) for status in unit_statuses
        ):
            return False

        if not unit_statuses and unit.workload_status.value != "active":
            return False

        if unit.agent_status.since + timedelta(seconds=idle_period) > datetime.now():
            return False

    return True


async def _is_every_condition_met(
    juju: jubilant.Juju,
    apps: List[str],
    wait_for_exact_units: Dict[str, int],
    apps_statuses: dict[str, list[StatusObject]] | None,
    units_statuses: dict[str, list[StatusObject]] | None,
    idle_period: int = 30,
) -> bool:
    """Evaluate if all the deployment status conditions are met."""
    for app in apps:
        app_dict = get_raw_application(juju, app)
        expected_units = wait_for_exact_units[app]
        if "subordinate-to" in app_dict:
            logger.debug(f"Subordinate app: {app}")
            # In this case, we must search for the principal app
            units = await get_application_subordinate_units(
                juju, app_dict["subordinate-to"][0], app
            )
        else:
            logger.debug(f"This is a principal app: {app}")
            units = await get_application_units(juju, app)

        if -1 < expected_units != len(units):
            logger.info(f"{app} -- expected units: {expected_units} -- current: {len(units)}")
            return False

        if not _is_every_condition_on_app_met(
            juju=juju,
            app=app,
            units=(units if expected_units > -1 else None),
            app_statuses=apps_statuses.get(app) if apps_statuses else None,
        ):
            logger.info(f"\tApp: {app} - conditions unmet.")
            logger.info(_progress_line(units))
            return False

        if expected_units > -1 and not _is_every_condition_on_units_met(
            model=_model_name(juju),
            units=units,
            unit_statuses=units_statuses.get(app) if units_statuses else None,
            idle_period=idle_period,
        ):
            logger.info(f"\tApp: {app} - Units - conditions unmet.")
            logger.info(_progress_line(units))
            return False

    return True


async def wait_until(  # noqa: C901
    juju: jubilant.Juju,
    apps: list[str],
    apps_statuses: dict[str, list[StatusObject]] | None = None,
    units_statuses: dict[str, list[StatusObject]] | None = None,
    wait_for_exact_units: int | dict[str, int] | None = -1,
    idle_period: int = 30,
    timeout: int = 1200,
) -> None:
    """Block and wait until a set of statuses and timeouts are met.

    Args:
        juju: The jubilant Juju instance
        apps: A list of applications whose statuses to test against
        apps_statuses: List of acceptable statuses to wait for by each specified app.
            The final computed status (e.g. that one shown in juju status) is only checked.
            All unspecified apps automatically checked for active status.
            Example: {APP_NAME: [GeneralStatuses.JWT_RELATION_INVALID.value]}
        units_statuses: List of acceptable statuses to wait for all units by each specified app.
            The final computed status (e.g. that one shown in juju status) is only checked.
            All unspecified apps automatically checked for active status of all units.
            Example: {APP_NAME: [ProfileStatuses.MISSING_PROFILE_REQUIREMENTS.value]}
        wait_for_exact_units: The desired number of units to wait for, can be >= to -1
            if set as int, this value is expected for all apps but if more granularity is needed to
            be set, pass a dictionary such as: {"app1": 2, "app2": 1, ...}, if set to -1, the check
            only happens at the application level.
        idle_period: Seconds to wait for the agents of each application unit to be idle.
        timeout: Time to wait before giving up on waiting.
    """
    if not apps:
        raise ValueError("apps must be specified.")
    if isinstance(wait_for_exact_units, int):
        wait_for_exact_units = {app: wait_for_exact_units for app in apps}
    elif not wait_for_exact_units:
        wait_for_exact_units = {app: -1 for app in apps}
    else:
        for app in apps:
            if app not in wait_for_exact_units:
                wait_for_exact_units[app] = 1
    try:
        logger.info("\n\n\n")
        logger.info(
            subprocess.check_output(f"juju status --model {_model_name(juju)}", shell=True).decode(
                "utf-8"
            )
        )
        for attempt in Retrying(stop=stop_after_delay(timeout), wait=wait_fixed(10)):
            with attempt:
                logger.info(f"\n\n\n{now()} -- Waiting for model...")
                if await _is_every_condition_met(
                    juju=juju,
                    apps=apps,
                    wait_for_exact_units=wait_for_exact_units,
                    apps_statuses=apps_statuses,
                    units_statuses=units_statuses,
                    idle_period=idle_period,
                ):
                    logger.info(f"{now()} -- Waiting for model: complete.\n\n\n")
                    return
                raise Exception
    except RetryError:
        logger.error("wait_until -- Timed out!\n\n\n")
        logger.info(
            subprocess.check_output(f"juju status --model {_model_name(juju)}", shell=True).decode(
                "utf-8"
            )
        )
        _dump_juju_logs(model=_model_name(juju), lines=3000)
        raise


async def wait_until_condition_on_units(
    juju: jubilant.Juju, app: str, condition: Callable[[list[Unit]], bool], timeout: int = 1200
) -> None:
    """Block and wait until a condition is met on the units in `app` or timeout."""
    try:
        logger.info("\n\n\n")
        logger.info(
            subprocess.check_output(f"juju status --model {_model_name(juju)}", shell=True).decode(
                "utf-8"
            )
        )
        for attempt in Retrying(stop=stop_after_delay(timeout), wait=wait_fixed(10)):
            with attempt:
                logger.info("Waiting for condition...")
                units = await get_application_units(juju, app)
                if condition(units):
                    logger.info(f"{now()} -- Waiting for condition: complete.\n\n\n")
                    return
                raise Exception
    except RetryError:
        logger.error("wait_until_condition_on_units -- Timed out!\n\n\n")
        logger.info(
            subprocess.check_output(f"juju status --model {_model_name(juju)}", shell=True).decode(
                "utf-8"
            )
        )
        _dump_juju_logs(model=_model_name(juju), lines=3000)
        raise


async def get_application_unit_ids_ips(juju: jubilant.Juju, app: str = APP_NAME) -> Dict[int, str]:
    """List the units of an application by id and corresponding IP.

    Args:
        juju: The jubilant Juju instance
        app: the name of the app

    Returns:
        Dictionary unit_id / IP, of the application
    """
    result = {}
    for unit in await get_application_units(juju, app):
        result[unit.id] = unit.ip

    return result


async def get_application_unit_ids_hostnames(
    juju: jubilant.Juju, app: str = APP_NAME
) -> Dict[int, str]:
    """List the units of an application by id and corresponding host name."""
    result = {}
    for unit_name in get_raw_application(juju, app).get("units", {}):
        unit_id = int(unit_name.split("/")[1])
        result[unit_id] = await get_unit_hostname(juju, unit_id, app)

    return result


def get_application_unit_ids(juju: jubilant.Juju, app: str = APP_NAME) -> List[int]:
    """List the unit IDs of an application.

    Args:
        juju: The jubilant Juju instance
        app: the name of the app

    Returns:
        list of current unit ids of the application
    """
    return [
        int(unit_name.split("/")[1])
        for unit_name in get_raw_application(juju, app).get("units", {})
    ]


def get_file_contents(
    juju: jubilant.Juju, unit: str, filename: str, substrate: Substrate = "vm"
) -> str:
    """Read file contents from a unit."""
    if substrate == "k8s":
        return juju.ssh(unit, "cat", filename, container="opensearch")
    return juju.ssh(unit, "sudo", "cat", filename)


def get_conf_as_dict(
    juju: jubilant.Juju, unit: str, filename: str, substrate: Substrate = "vm"
) -> dict[str, str]:
    """Convert a yml config file to a dict."""
    config = get_file_contents(juju, unit, filename, substrate)
    return yaml.safe_load(config.replace("ll", ""))


async def get_leader_unit_id(juju: jubilant.Juju, app: str = APP_NAME) -> int:
    """Helper function that retrieves the leader unit ID."""
    for unit_name, unit in juju.status().apps[app].units.items():
        if unit.leader:
            return int(unit_name.split("/")[1])


async def get_leader_unit_ip(juju: jubilant.Juju, app: str = APP_NAME) -> str:
    """Helper function that retrieves the leader unit IP."""
    for unit in await get_application_units(juju, app):
        if unit.is_leader:
            return unit.ip


async def _find_k8s_unit_for_endpoint(
    juju: jubilant.Juju, endpoint: str, app: str
) -> Optional[Unit]:
    """Return the K8s unit matching the endpoint host, if any."""
    if not _is_k8s(juju):
        return None

    hostname = urlparse(endpoint).hostname
    if not hostname:
        return None

    for unit in await get_application_units(juju, app):
        # On K8s the pod hostname is the Juju short unit name, e.g. `opensearch-0`.
        # We use that as the signal to run requests from inside the pod so TLS can
        # use the pod DNS name rather than the external pod IP.
        if unit.ip == hostname:
            return unit

    return None


def _request_path(endpoint: str) -> str:
    """Return the path and query string for an HTTP endpoint."""
    parsed_endpoint = urlparse(endpoint)
    path = parsed_endpoint.path or "/"
    return f"{path}?{parsed_endpoint.query}" if parsed_endpoint.query else path


def _k8s_unit_fqdn(juju: jubilant.Juju, app: str, unit: Unit) -> str:
    """Return the fully qualified domain name for a K8s unit"""
    return f"{unit.short_name}.{app}-endpoints.{_model_name(juju)}.svc.cluster.local"


def _http_request_headers(
    json_resp: bool,
    extra_headers: Optional[Dict[str, Any]] = None,
) -> dict[str, Any]:
    """Build headers used by http_request."""
    headers: dict[str, Any] = {}
    if json_resp:
        headers.update(
            {
                "Accept": "application/json",
                "Content-Type": "application/json",
            }
        )
    if extra_headers:
        headers.update(extra_headers)
    return headers


@retry(wait=wait_fixed(wait=15), stop=stop_after_attempt(15))
async def run_action(  # noqa: C901
    juju: jubilant.Juju,
    unit_id: Optional[int],
    action_name: str,
    params: Optional[Dict[str, any]] = None,
    app: str = APP_NAME,
) -> SimpleNamespace:
    """Run a charm action.

    Returns:
        A SimpleNamespace with "status, response (results)"
    """
    if app not in juju.status().apps:
        return SimpleNamespace(
            status="failed",
            response={"error": f"Application {app} not found in model {_model_name(juju)}"},
        )
    if unit_id is None:
        online_units = []
        for unit in await get_application_units(juju, app):
            if unit.workload_status.value != "active":
                continue

            # K8s units do not expose SSH on port 22, so Juju actions should target
            # any active unit directly.
            # try to juju exec
            if _is_k8s(juju):
                try:
                    task = juju.exec("echo hello", unit=f"{app}/{unit.id}", wait=5)
                    if task.return_code == 0 and task.stdout.strip() == "hello":
                        online_units.append(unit)
                except jubilant.TaskError:
                    pass
                continue

            ping = subprocess.call(
                f"nc -zv {unit.ip} 22".split(),
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            if ping == 0:
                online_units.append(unit)

        if not online_units:
            raise RuntimeError(
                f"No active units available to run action {action_name} on app {app}."
            )

        unit_id = random.choice(online_units).id

    unit_name = f"{app}/{unit_id}"

    try:
        task = juju.run(unit_name, action_name, params or {})
    except jubilant.TaskError as e:
        return SimpleNamespace(status="failed", response=e.task.results)
    except jubilant.CLIError as e:
        return SimpleNamespace(status="failed", response={"error": str(e)})

    return SimpleNamespace(status=task.status or "completed", response=task.results)


async def get_secrets(
    juju: jubilant.Juju,
    unit_id: Optional[int] = None,
    username: str = "admin",
    app: str = APP_NAME,
) -> Dict[str, str]:
    """Use the charm action to retrieve the admin password and chain.

    Returns:
        Dict with the admin and cert chain stored on the peer relation databag.
    """
    # can retrieve from any unit running unit, so we pick the first
    return (
        await run_action(juju, unit_id, "get-password", {"username": username}, app=app)
    ).response


async def http_request(  # noqa: C901
    juju: jubilant.Juju,
    method: str,
    endpoint: str,
    payload: Optional[Union[str, Dict[str, any]]] = None,
    resp_status_code: bool = False,
    verify=True,
    user: Optional[str] = "admin",
    user_password: Optional[str] = None,
    app: str = APP_NAME,
    json_resp: bool = True,
    extra_headers: Optional[Dict[str, any]] = None,
    timeout: float = 30.0,
):
    """Makes an HTTP request.

    Args:
        juju: The jubilant Juju instance.
        method: the HTTP method (GET, POST, HEAD etc.)
        endpoint: the url to be called.
        payload: the body of the request if any.
        resp_status_code: whether to only return the http response code.
        verify: whether verify certificate chain or not
        user_password: use alternative password than the admin one in the secrets.
        app: the name of the current application.
        json_resp: return a json response or simply log

    Returns:
        A json object.
    """
    admin_secrets = await get_secrets(juju, app=app)
    if _is_k8s(juju):
        k8s_unit = await _find_k8s_unit_for_endpoint(juju, endpoint, app)
        if not k8s_unit:
            raise RuntimeError(
                f"No unit found for endpoint {endpoint}. Cannot make request from {CLIENT_CHARM}."
            )
        # K8s requests that start from a pod IP are executed from inside the
        # cluster so they can use the stable unit service DNS name with strict TLS.
        logger.info(
            f"Calling through {CLIENT_CHARM} for {k8s_unit.name}: {method} - {_k8s_unit_fqdn(juju, app, k8s_unit)} route: {_request_path(endpoint)}"
        )
        params: dict[str, Any] = {
            "method": method,
            "route": _request_path(endpoint),
            "host": _k8s_unit_fqdn(juju, app, k8s_unit),
            "ca_cert": base64.b64encode(admin_secrets["ca-chain"].encode()).decode(),
            "timeout": int(timeout),
        }
        if payload is not None:
            params["body"] = json.dumps(payload)
        if user is not None:
            params["username"] = user
            params["password"] = user_password or admin_secrets["password"]
        if not verify:
            params["verify"] = False
        if headers := _http_request_headers(json_resp, extra_headers):
            params["headers"] = json.dumps(headers)

        action = await run_action(
            juju,
            None,
            "request",
            params,
            app=CLIENT_CHARM,
        )
        if action.status != "completed":
            raise RuntimeError(
                f"{CLIENT_CHARM} request action failed with status {action.status}: "
                f"{action.response}"
            )

        status_code = action.response["status-code"]
        body = action.response["body"]
        if resp_status_code:
            return int(status_code)
        if json_resp:
            return json.loads(body)
        logger.info(f"\n{body}")
        return SimpleNamespace(
            content=body.encode("utf-8"),
            status_code=status_code,
            text=body,
        )

    # fetch the cluster info from the endpoint of this unit
    with requests.Session() as session, tempfile.NamedTemporaryFile(mode="w+") as chain:
        chain.write(admin_secrets["ca-chain"])
        chain.seek(0)

        logger.info(f"Calling: {method} -- {endpoint}")

        request_kwargs = {
            "method": method,
            "url": endpoint,
            "timeout": timeout,
        }
        headers = _http_request_headers(json_resp, extra_headers)

        if headers:
            request_kwargs["headers"] = headers

        if isinstance(payload, str):
            request_kwargs["data"] = payload
        elif isinstance(payload, dict):
            request_kwargs["data"] = json.dumps(payload)

        session.auth = (user, user_password or admin_secrets["password"])

        request_kwargs["verify"] = chain.name if verify else False
        resp = session.request(**request_kwargs)

        if resp.status_code == 503:
            logger.debug("\n\n\n\n -- Error 503 -- \n")
            await debug_failed_unit(juju, app, endpoint)

        if resp_status_code:
            return resp.status_code

        if json_resp:
            return resp.json()

        logger.info(f"\n{resp.text}")
        return resp


async def debug_failed_unit(juju: jubilant.Juju, app: str, endpoint: str) -> None:
    """Print the logs of a unit failing with a certain set of statuses."""
    unit_ip = endpoint[8:].split(":")[0]

    ids_ips = await get_application_unit_ids_ips(juju, app=app)
    unit_id = [u_id for u_id, u_ip in ids_ips.items() if u_ip == unit_ip][0]

    root = "/var/snap/opensearch"
    files_to_debug = [
        f"{root}/common/logs/{app}-{_model_name(juju)}.log",
        f"{root}/current/config/opensearch.yml",
        f"{root}/current/config/unicast_hosts.txt",
    ]
    for f in files_to_debug:
        logger.debug(f"{f}:\n")

        try:
            out = juju.ssh(f"{app}/{unit_id}", "sudo", "cat", f)
            logger.debug(f"out:\n{out}")
        except jubilant.CLIError as err:
            logger.debug(f"err:\n{err}")

        logger.debug("\n\n------------------\n\n")


def opensearch_client(
    hosts: List[str], user_name: str, password: str, cert_path: str
) -> OpenSearch:
    """Build an opensearch client."""
    return OpenSearch(
        hosts=[{"host": ip, "port": 9200} for ip in hosts],
        http_auth=(user_name, password),
        http_compress=True,
        # Integration tests already pass the current unit IPs explicitly.
        # Node sniffing asks OpenSearch for the full node list and
        # replaces the client's seed hosts with the discovered addresses.
        # The discovered node endpoints are commonly pod IPs or cluster-local DNS names,
        # and the runner outside Kubernetes cannot reliably use them.
        # Disable it here because it is brittle during CA rotation and can fail
        # before the client ever attempts the provided hosts.
        use_ssl=True,  # turn on ssl
        verify_certs=True,  # make sure we verify SSL certificates
        ssl_assert_hostname=False,
        ssl_show_warn=False,
        ca_certs=cert_path,  # cert path on disk
        retry_on_timeout=True,
        max_retries=3,
    )


async def get_application_unit_ips(juju: jubilant.Juju, app: str = APP_NAME) -> List[str]:
    """List the unit IPs of an application.

    Args:
        juju: The jubilant Juju instance
        app: the name of the app

    Returns:
        list of current IPs of the application
    """
    return [unit.ip for unit in await get_application_units(juju, app)]


async def get_secret_by_label(juju: jubilant.Juju, label: str) -> Dict[str, str]:
    secrets_raw = juju.cli("list-secrets")
    secret_ids = [
        secret_line.split()[0] for secret_line in secrets_raw.split("\n")[1:] if secret_line
    ]

    for secret_id in secret_ids:
        secret_data_raw = juju.cli("show-secret", "--format", "json", "--reveal", secret_id)
        secret_data = json.loads(secret_data_raw)

        if label == secret_data[secret_id].get("label"):
            return secret_data[secret_id]["content"]["Data"]


@retry(
    wait=wait_fixed(wait=5) + wait_random(0, 5),
    stop=stop_after_attempt(15),
)
async def check_cluster_formation_successful(
    juju: jubilant.Juju, unit_ip: str, unit_names: list[str], app: str = APP_NAME
) -> bool:
    """Returns whether the cluster formation was successful and all nodes successfully joined.

    Args:
        juju: The jubilant Juju instance.
        unit_ip: The ip of the unit of the OpenSearch unit.
        unit_names: The list of unit names in the cluster.

    Returns:
        Whether The cluster formation is successful.
    """
    response = await http_request(juju, "GET", f"https://{unit_ip}:9200/_nodes", app=app)
    if "_nodes" not in response or "nodes" not in response:
        return False

    successful_nodes = response["_nodes"]["successful"]
    if successful_nodes < len(unit_names):
        return False

    registered_nodes = [node_desc["name"] for node_desc in response["nodes"].values()]
    return set(unit_names) == set(registered_nodes)


@retry(
    wait=wait_fixed(wait=5) + wait_random(0, 5),
    stop=stop_after_attempt(15),
)
async def cluster_health(
    juju: jubilant.Juju, unit_ip: str, wait_for_green_first: bool = False, app: str = APP_NAME
) -> Dict[str, any]:
    """Fetch the cluster health."""
    if wait_for_green_first:
        try:
            return await http_request(
                juju,
                "GET",
                f"https://{unit_ip}:9200/_cluster/health?wait_for_status=green&timeout=1m",
                app=app,
            )
        except requests.HTTPError:
            # it timed out, settle with current status, fetched next without the 1min wait
            pass

    return await http_request(
        juju,
        "GET",
        f"https://{unit_ip}:9200/_cluster/health",
        app=app,
    )


async def get_application_unit_ips_names(
    juju: jubilant.Juju, app: str = APP_NAME
) -> Dict[str, str]:
    """List the units of an application by name and corresponding IPs.

    Args:
        juju: The jubilant Juju instance
        app: the name of the app

    Returns:
        Dictionary unit_name / IP, of the application
    """
    result = {}
    for unit in await get_application_units(juju, app):
        result[unit.name] = unit.ip

    return result


def get_application_unit_names(juju: jubilant.Juju, app: str = APP_NAME) -> List[str]:
    """List the unit names of an application.

    Args:
        juju: The jubilant Juju instance
        app: the name of the app

    Returns:
        list of current unit names of the application
    """
    app_id = f"{_model_uuid(juju)}/{app}"
    app_short_id = md5(app_id.encode()).hexdigest()[:3]
    return [
        f"{unit_name.replace('/', '-')}.{app_short_id}"
        for unit_name in get_raw_application(juju, app).get("units", {})
    ]


@retry(
    wait=wait_fixed(wait=15) + wait_random(0, 5),
    stop=stop_after_attempt(25),
)
async def cluster_voting_config_exclusions(
    juju: jubilant.Juju, unit_ip: str, app: str = APP_NAME
) -> list[dict[str, str]]:
    """Fetch the cluster allocation of shards."""
    result = await http_request(
        juju,
        "GET",
        f"https://{unit_ip}:9200/_cluster/state/metadata/voting_config_exclusions",
        app=app,
    )
    return (
        result.get("metadata", {})
        .get("cluster_coordination", {})
        .get("voting_config_exclusions", {})
    )


async def execute_update_status_manually(juju: jubilant.Juju, app: str):
    """Execute the update-status hook manually."""
    leader_id = await get_leader_unit_id(juju, app)

    cmd = '"export JUJU_DISPATCH_PATH=hooks/update-status; ./dispatch"'
    exec_cmd = f"juju exec -u opensearch/{leader_id} -m {_model_name(juju)} -- {cmd}"
    try:
        # The "normal" subprocess.run with "export ...; ..." cmd was failing
        # Noticed that, for this case, canonical/jhack uses shlex instead to split.
        # Adding it fixed the issue.
        subprocess.run(shlex.split(exec_cmd))
    except Exception as e:
        logger.error(
            f"Failed to apply state: process exited with {e.returncode}; "
            f"stdout = {e.stdout}; "
            f"stderr = {e.stderr}.",
        )


@retry(wait=wait_fixed(wait=30), stop=stop_after_attempt(15))
async def set_watermark(
    juju: jubilant.Juju,
    app: str,
) -> None:
    """Set watermark on the application."""
    unit_ip = await get_leader_unit_ip(juju, app=app)
    await http_request(
        juju,
        "PUT",
        f"https://{unit_ip}:9200/_cluster/settings",
        {
            "persistent": {
                "cluster.routing.allocation.disk.threshold_enabled": "false",
            }
        },
        app=app,
    )


def is_reachable(host: str, port: int) -> bool:
    """Attempting a socket connection to a host/port."""
    s = socket.socket()
    s.settimeout(5)
    try:
        s.connect((host, port))
        return True
    except Exception as e:
        logger.debug(f"Connection to {host}:{port} fails with: {e}")
        return False
    finally:
        s.close()


async def is_up(
    juju: jubilant.Juju,
    unit_ip: str,
    retries: int = 25,
    app: str = APP_NAME,
    timeout: float = 30.0,
) -> bool:
    """Return if node up."""
    try:
        for attempt in Retrying(stop=stop_after_attempt(retries), wait=wait_fixed(wait=15)):
            with attempt:
                await http_request(
                    juju, "GET", f"https://{unit_ip}:9200/", app=app, timeout=timeout
                )
                return True
    except RetryError:
        pass
    return False


async def get_reachable_unit_ips(juju: jubilant.Juju, app: str = APP_NAME) -> List[str]:
    """Helper function to retrieve the IP addresses of all online units."""
    result = []
    for ip in await get_application_unit_ips(juju, app):
        if not is_reachable(ip, 9200):
            continue

        if await is_up(juju, ip, retries=1):
            result.append(ip)

    return result


def juju_version_major() -> int:
    """Fetch the juju version."""
    version = subprocess.run(["juju", "--version"], check=True, stdout=subprocess.PIPE).stdout
    return int(version.strip().decode("utf-8").split(".")[0])


async def get_controller_hostname(juju: jubilant.Juju) -> str:
    """Return controller machine hostname."""
    raw_controller = juju.cli("show-controller", include_model=False)

    controller = yaml.safe_load(raw_controller.strip())
    controller_name = next(iter(controller))

    return [
        machine.get("instance-id")
        for machine in controller[controller_name]["controller-machines"].values()
    ][0]


async def app_name(juju: jubilant.Juju) -> str | None:
    """Returns the name of the cluster running OpenSearch.

    This is important since not all deployments of the OpenSearch charm have the
    application name "opensearch".
    Note: if multiple clusters are running OpenSearch this will return the one first found.
    """
    apps = json.loads(
        subprocess.check_output(f"juju status --model {_model_name(juju)} --format=json".split())
    )["applications"]

    logger.info(f"Apps inside app_name: {apps}")

    # Integration tests can run against both the VM charm (opensearch) and the K8s charm
    # (opensearch-k8s). Match both.
    opensearch_charm_names = {"opensearch", "opensearch-k8s"}
    opensearch_apps = {
        name: desc
        for name, desc in apps.items()
        if desc.get("charm-name") in opensearch_charm_names
    }
    for name, desc in opensearch_apps.items():
        if name == "opensearch-main":
            return name

    return list(opensearch_apps.keys())[0] if opensearch_apps else None


async def get_unit_relation_data(
    juju: jubilant.Juju,
    unit_name: str,
    target_unit_name: str,
    relation_name: str,
    key: str,
    relation_id: str = None,
) -> Optional[str]:
    """Get relation data for an application.

    Args:
        juju: The jubilant Juju instance
        unit_name: The name of the unit
        target_unit_name: The name of the related unit
        relation_name: name of the relation to get connection data from
        key: key of data to be retrieved
        relation_id: id of the relation to get connection data from

    Returns:
        the data that was requested or None
            if no data in the relation

    Raises:
        ValueError if it's not possible to get application unit data
            or if there is no data for the particular relation endpoint
            and/or alias.
    """
    raw_data = juju.cli("show-unit", unit_name)
    if not raw_data:
        raise ValueError(f"no unit info could be grabbed for {unit_name}")
    data = yaml.safe_load(raw_data)
    # Filter the data based on the relation name.
    relation_data = [v for v in data[unit_name]["relation-info"] if v["endpoint"] == relation_name]
    if relation_id:
        # Filter the data based on the relation id.
        relation_data = [v for v in relation_data if v["relation-id"] == relation_id]
    if not relation_data:
        raise ValueError(
            f"no relation data could be grabbed on relation with endpoint {relation_name}"
        )
    # Consider the case we are dealing with subordinate charms, e.g. grafana-agent
    # The field "relation-units" is structured slightly different.
    for idx in range(len(relation_data)):
        if target_unit_name in relation_data[idx]["related-units"]:
            break
    else:
        return {}
    return (
        relation_data[idx]["related-units"].get(target_unit_name, {}).get("data", {}).get(key, {})
    )
