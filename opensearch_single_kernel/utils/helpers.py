#!/usr/bin/env python3
# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""A set of helpers functions."""

import base64
import errno
import hashlib
import json
import logging
import math
import re
import secrets
import socket
import string
import threading
from collections.abc import Iterable
from datetime import datetime
from typing import Any

import bcrypt
from cryptography import x509
from ops import Unit, pebble

from opensearch_single_kernel.common.constants import (
    PROTECTED_INDEX_NAMES,
    DeploymentType,
    StartMode,
)
from opensearch_single_kernel.common.exceptions import OpenSearchCmdError
from opensearch_single_kernel.core.base_models import (
    App,
    PeerClusterConfig,
)

logger = logging.getLogger(__name__)


def format_unit_name(unit: Unit | str, app: App) -> str:
    """Format unit_name according the app."""
    if isinstance(unit, Unit):
        unit = unit.name
    return f"{unit.replace('/', '-')}.{app.short_id}"


def mask_sensitive_information(cmd: str) -> str:
    """Replace passwords or secrets by 'xxx' and return the masked str."""
    pattern = re.compile(r"(-tspass\s+|-kspass\s+|-storepass\s+|-new\s+|pass:)(\S+)")

    return re.sub(pattern, r"\1" + "xxx", cmd)


def hash_string(string: str) -> str:
    """Hashes the given string."""
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(string.encode("utf-8"), salt)
    return hashed.decode("utf-8")


def generate_password() -> str:
    """Generate a random password string.

    Returns:
       A random password string.
    """
    choices = string.ascii_letters + string.digits
    return "".join([secrets.choice(choices) for _ in range(32)])


def generate_hashed_password(pwd: str | None = None) -> tuple[str, str]:
    """Generates a password and its bcrypt hash.

    Returns:
        A hash and the original password
    """
    pwd = pwd or generate_password()
    return hash_string(pwd), pwd


def deployment_type(
    config: PeerClusterConfig,
    start_mode: StartMode,
    prev_deployment_type: DeploymentType | None = None,
) -> DeploymentType:
    """Check if the current cluster is an independent cluster."""
    has_cm_roles = (
        start_mode == StartMode.WITH_GENERATED_ROLES or "cluster_manager" in config.roles
    )
    if not has_cm_roles:
        return DeploymentType.OTHER

    return prev_deployment_type or (
        DeploymentType.MAIN_ORCHESTRATOR
        if not config.init_hold
        else DeploymentType.FAILOVER_ORCHESTRATOR
    )


def get_k8s_fqdn(name: str) -> str:
    """Resolve the canonical FQDN for a Kubernetes service or pod name."""
    try:
        info = socket.getaddrinfo(
            name,
            None,
            family=socket.AF_UNSPEC,
            flags=socket.AI_CANONNAME,
            type=socket.SOCK_STREAM,
        )
    except socket.gaierror as e:
        logger.warning(
            "Failed to resolve canonical name for %s: %s. \nFalling back on default fqdn.",
            name,
            e,
        )
        return socket.getfqdn(name)

    for entry in info:
        if canonname := entry[3]:
            return canonname

    logger.warning(
        "Failed to resolve canonical name for %s. \nFalling back on default fqdn.", name
    )
    return socket.getfqdn(name)


def k8s_fqdn(unit_name: str | None) -> str:
    """Return the canonical K8s seed host for a unit."""
    # Strip Juju short id / DNS suffix: "app-0.c67", FQDNs -> pod hostname prefix.
    pod_prefix = (unit_name or "").split(".", 1)[0]
    # remove the last -digit to get the app name: "app-0" -> "app"
    app_name = "-".join(pod_prefix.split("-")[:-1])
    service_name = f"{pod_prefix}.{app_name}-endpoints"
    return get_k8s_fqdn(service_name)


def normalized_tls_subject(subject: str) -> str:
    """Removes any / character from a subject."""
    if subject.startswith("/"):
        subject = subject[1:]
    return subject.replace("/", ",")


def cert_expiration_remaining_hours(cert: str) -> int:
    """Returns the remaining hours for the cert to expire."""
    certificate_object = x509.load_pem_x509_certificate(data=cert.encode())
    time_difference = certificate_object.not_valid_after - datetime.utcnow()

    return math.floor(time_difference.total_seconds() / 3600)


def is_alias_missing_error(exc: OpenSearchCmdError, alias: str) -> bool:
    """Return True if keytool says that given alias does not exist.

    Args:
        exc: The OpenSearchCmdError to check.
        alias: The alias that was attempted to be deleted.

    Returns:
        bool: True if the error message indicates that the alias does not exist.
    """
    msg = (exc.out or "") + (exc.err or "")
    return f"Alias <{alias}> does not exist" in msg


def parse_tls_file(raw_content: str) -> bytes:
    """Parse TLS files from both plain text or base64 format."""
    if re.match(r"(-+(BEGIN|END) [A-Z ]+-+)", raw_content):
        return re.sub(
            r"(-+(BEGIN|END) [A-Z ]+-+)",
            "\\1",
            raw_content,
        ).encode("utf-8")
    return base64.b64decode(raw_content)


def validate_index_name(index_name: str) -> bool:
    """Validates that the index name provided in the relation is acceptable."""
    if index_name in PROTECTED_INDEX_NAMES:
        logger.error(
            "invalid index name %s - tried to access a protected index in %s",
            index_name,
            PROTECTED_INDEX_NAMES,
        )
        return False

    if not index_name.islower():
        logger.error("invalid index name %s - index names must be lowercase", index_name)
        return False

    forbidden_chars = [" ", ",", ":", '"', "*", "+", "\\", "/", "|", "?", "#", ">", "<"]
    if any([char in index_name for char in forbidden_chars]):
        logger.error(
            "invalid index name %s - index name includes one or more of "
            "the following forbidden characters: %s",
            index_name,
            forbidden_chars,
        )
        return False

    return True


def diff(desired: Iterable[str], current: Iterable[str]) -> tuple[set[str], set[str]]:
    """Returns diff needed to turn current list into desired list"""
    desired_labels = set(desired)
    current_labels = set(current)

    add = desired_labels - current_labels
    remove = current_labels - desired_labels
    return add, remove


def decode_plugin_secret_content(content: dict, label: str) -> dict[str, str] | None:
    """Decodes JSON payload from plugin secret

    Args:
        content: dictionary of the secret content
        label: label of the secfet

    Returns:
        A decoded dictionary if successful, else None
    """
    if not (raw := content.get(label)):
        logger.warning("Key '%s' not found in secret content", label)
        return None

    try:
        return json.loads(raw)
    except json.JSONDecodeError as e:
        logger.error("Malformed JSON in secret %s: %s", label, e)
        return None


def build_command_list(command_with_args: str) -> list[str]:
    """Build command list for container.exec().

    Detects shell metacharacters and wraps command in shell if needed.
    Otherwise splits command into list of arguments.

    Args:
        command_with_args: Full command string with arguments.

    Returns:
        list[str]: Command list suitable for container.exec().
    """
    shell_metachars = ["|", ">", "<", "&&", "||", ";", "$(", "${", "`", "2>", ">>", "<<", "&"]
    if any(char in command_with_args for char in shell_metachars):
        return ["sh", "-c", command_with_args]
    if " " in command_with_args:
        return command_with_args.split()
    return [command_with_args]


# Validated against ops/pebble 3.7.1; ExecProcess exposes these private
# attributes used by the best-effort teardown below.
_EXEC_THREAD_JOIN_TIMEOUT = 5


def _is_expected_exec_teardown_error(exc: BaseException | None) -> bool:
    """Return True if exc is the expected fallout of shutting an exec websocket.

    When we deliberately shut down a Pebble exec websocket (see
    `_cleanup_exec_process`), the pump thread blocked in ``ws.recv()`` wakes up
    and raises. Those raises are expected and benign; everything else should
    keep the default behaviour.
    """
    if exc is None:
        return False
    # websocket-client raises these when recv() hits a closed socket. Match by
    # name on purpose: it keeps this helper usable VM-side where the websocket
    # package (a Pebble-only transitive dependency) may not be importable.
    return (
        type(exc).__name__ in {"WebSocketConnectionClosedException", "WebSocketTimeoutException"}
        or isinstance(exc, (BrokenPipeError, ConnectionError))
        or (isinstance(exc, OSError) and exc.errno == errno.EBADF)
    )


def _raised_in_pebble_pump(traceback: Any) -> bool:
    """Return True if the traceback runs through a Pebble exec pump thread.

    The pump threads are ``shutil.copyfileobj`` reading a Pebble websocket, so
    their traceback always passes through ``ops.pebble`` (and usually
    ``websocket``). Checking the originating module keeps suppression scoped to
    those threads rather than every thread in the process.
    """
    tb = traceback
    while tb is not None:
        module = tb.tb_frame.f_globals.get("__name__", "")
        if module.startswith("ops.pebble") or module.startswith("websocket"):
            return True
        tb = tb.tb_next
    return False


_excepthook_lock = threading.Lock()
_excepthook_installed = False


def _install_pebble_pump_excepthook() -> None:
    """Install (once) a ``threading.excepthook`` that silences pump-thread noise.

    When we shut a Pebble exec websocket down during teardown, the pump thread
    blocked in ``ws.recv()`` raises ``WebSocketConnectionClosedException``. Unlike
    the success path, ``ws.shutdown()`` (a bare ``socket.close()``) does not
    reliably interrupt a thread already blocked in the OS ``recv()`` syscall, so
    the raise can land *after* teardown returns -- or not until interpreter
    shutdown. Suppression therefore has to be persistent, not scoped to the
    teardown call, which is why this installs a long-lived hook instead of using
    a context manager.

    The hook is deliberately narrow: it only swallows the expected
    websocket-close error types *and* only when the traceback originates in
    ``ops.pebble``/``websocket``. Everything else falls through to the previous
    hook, so unrelated thread exceptions are untouched. Installation is
    idempotent and guarded by a lock so repeated teardowns don't chain hooks.
    """
    global _excepthook_installed
    with _excepthook_lock:
        if _excepthook_installed:
            return
        previous_hook = threading.excepthook

        def hook(args: threading.ExceptHookArgs) -> None:
            if _is_expected_exec_teardown_error(args.exc_value) and _raised_in_pebble_pump(
                args.exc_traceback
            ):
                logger.debug(
                    "Suppressed expected Pebble exec I/O thread error: %r", args.exc_value
                )
                return
            previous_hook(args)

        threading.excepthook = hook
        _excepthook_installed = True


def _cancel_exec_stdin(process: Any) -> None:
    """Stop the stdin pump thread, if exec was given stdin."""
    if (cancel_stdin := getattr(process, "_cancel_stdin", None)) is None:
        return
    try:
        cancel_stdin()
    except Exception as cleanup_error:  # noqa: BLE001 - best effort teardown
        logger.debug("Failed to cancel exec stdin during cleanup: %s", cleanup_error)


def _shutdown_exec_websockets(process: Any) -> None:
    """Shut down the exec websockets so blocked pump threads wake up."""
    for ws_attr in ("_stdio_ws", "_stderr_ws", "_control_ws"):
        try:
            ws = getattr(process, ws_attr)
        except AttributeError:
            logger.warning(
                "Pebble ExecProcess has no %s; exec teardown may be incomplete "
                "(ops version change?)",
                ws_attr,
            )
            continue
        if ws is None:
            continue
        try:
            ws.shutdown()
        except Exception as cleanup_error:  # noqa: BLE001 - best effort teardown
            logger.debug("Failed to shut down exec %s during cleanup: %s", ws_attr, cleanup_error)


def _join_exec_threads(process: Any) -> None:
    """Join the exec I/O threads so they don't outlive the call."""
    try:
        threads = process._threads
    except AttributeError:
        logger.warning(
            "Pebble ExecProcess has no _threads; exec teardown may be incomplete "
            "(ops version change?)"
        )
        return
    for thread in threads or []:
        try:
            thread.join(timeout=_EXEC_THREAD_JOIN_TIMEOUT)
        except Exception as cleanup_error:  # noqa: BLE001 - best effort teardown
            logger.debug("Failed to join exec I/O thread during cleanup: %s", cleanup_error)
        if thread.is_alive():
            logger.warning("Exec I/O thread %s still alive after cleanup", thread.name)


def _cleanup_exec_process(process: Any) -> None:
    """Tear down the I/O threads/websockets of a Pebble exec process.

    Pebble's ``ExecProcess.wait_output()``/``wait()`` only join their internal
    I/O threads and shut down the websockets on the success path. If
    ``wait_change`` raises (e.g. the exec ``timeout`` elapses) the exception
    propagates before that cleanup runs, leaving the stdout/stderr/stdin pump
    threads blocked on websockets that are never closed. Those threads are
    created with the default ``daemon=False``, so they keep the interpreter
    alive: when the hook process tries to exit, ``threading._shutdown()`` blocks
    forever joining them (manifesting as a hang in ``lock.acquire()``).

    This best-effort cleanup cancels stdin, shuts the websockets down so the
    pump threads hit EOF, and joins them so they don't outlive the call. The
    pump threads raise ``WebSocketConnectionClosedException`` as they unwind,
    possibly after this returns, so we install a persistent excepthook to keep
    those expected errors out of the logs (see
    ``_install_pebble_pump_excepthook``).

    Args:
        process: the ``ExecProcess`` returned by ``container.exec()``.
    """
    _install_pebble_pump_excepthook()
    _cancel_exec_stdin(process)
    _shutdown_exec_websockets(process)
    _join_exec_threads(process)


def wait_for_process_output(
    process: Any, masked_command: str, original_command: str
) -> tuple[str, str]:
    """Wait for process to complete and return output.

    Args:
        process: Process object from container.exec() (has wait_output()).
        masked_command: Command string with sensitive info masked for logging.
        original_command: Original command string for error messages.

    Returns:
        tuple[str, str]: (stdout, stderr). stderr is typically empty when
        combine_stderr=True was used for exec().

    Raises:
        OpenSearchCmdError: If process fails or returns non-zero exit code.
    """
    try:
        stdout, stderr = process.wait_output()
        return stdout, stderr
    except pebble.ExecError as e:
        # 1. Safely extract and decode the raw, untruncated buffers
        out_raw = (
            e.stdout.decode("utf-8", "replace")
            if isinstance(e.stdout, bytes)
            else (e.stdout or "")
        )
        err_raw = (
            e.stderr.decode("utf-8", "replace")
            if isinstance(e.stderr, bytes)
            else (e.stderr or "")
        )

        # 2. Fall back to stdout if stderr is empty
        full_err_output = err_raw if err_raw else out_raw
        error_string = full_err_output.lower()
        # On failure (notably a timed-out exec), Pebble may leave its non-daemon
        # I/O threads running, which blocks interpreter shutdown. Tear them down.
        _cleanup_exec_process(process)
        missing_keystore = (
            "opensearch.keystore" in error_string and "does not exist" in error_string
        ) or "keystore file does not exist" in error_string
        if missing_keystore:
            logger.debug(
                "wait_output() failed for %s (expected missing opensearch.keystore): %s",
                masked_command,
                e,
            )
        else:
            logger.warning("wait_output() failed for %s: %s", masked_command, e)

        raise OpenSearchCmdError(cmd=original_command, out="", err=full_err_output) from None
    except Exception as e:
        _cleanup_exec_process(process)
        logger.warning("wait_output() failed unexpectedly for %s: %s", masked_command, e)
        raise OpenSearchCmdError(cmd=original_command, out="", err=str(e)) from None


def lock_unit_name(full_unit_id: str) -> str:
    """Build back the juju formatted unit name."""
    # we first take out the app id suffix
    full_unit_id_split = full_unit_id.split(".")[0].rsplit("-")
    return "{}/{}".format("-".join(full_unit_id_split[:-1]), full_unit_id_split[-1])


def hash_credentials(credentials: dict[str, str]) -> str:
    """Return a hash of the given credentials.

    Args:
        credentials: credentials in a dict

    Returns:
        hash of the credentials
    """
    return hashlib.sha1(json.dumps(credentials, sort_keys=True).encode()).hexdigest()
