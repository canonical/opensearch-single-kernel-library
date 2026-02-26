# K8s vs VM Substrate Comparison Guide

This document outlines the key differences between Kubernetes (K8s) and VM substrate implementations in the OpenSearch Single Kernel charm.

## Contents

1. [Workload Implementation](#1-workload-implementation)
2. [File System Paths](#2-file-system-paths)
3. [Node Configuration](#3-node-configuration)
4. [Network Configuration](#4-network-configuration)
5. [Service Management](#5-service-management)
6. [File Operations](#6-file-operations)
7. [System Requirements](#7-system-requirements)
8. [Container/Workload Readiness](#8-containerworkload-readiness)
9. [Certificate Handling](#9-certificate-handling)
10. [Event Handling](#10-event-handling)
11. [Changes in Managers and Event Handlers (code map)](#11-changes-in-managers-and-event-handlers)



## 1. Workload Implementation

### K8s
- Class: K8sWorkload (workload/k8s.py)
- Runtime: Pebble (container orchestration)
- Container: Uses ops.Container for container operations
- Service: Pebble service (opensearch)
- Image: Rock image (Ubuntu-based container image)


### VM
- Class: VMWorkload (workload/vm.py)
- Runtime: Snap (Ubuntu snap package)
- Container: N/A (direct filesystem access)
- Service: Snap service (opensearch.daemon)
- Package: Snap package (opensearch)




## 2. File System Paths

### K8s Paths
Uses standard Linux filesystem paths (rock image):

| Path Type | K8s Path | Notes |
|-----------|----------|-------|
| Home | /usr/share/opensearch | OpenSearch installation directory |
| Config | /etc/opensearch | Configuration files |
| Data (mount) | /var/lib/opensearch | K8s volume mount point |
| Data (used) | /var/lib/opensearch/data | OpenSearch `path.data` on K8s |
| Logs (mount) | /var/log/opensearch | K8s volume mount point |
| Logs (used) | /var/log/opensearch/logs | OpenSearch `path.logs` on K8s |
| JDK | /usr/lib/jvm/java-21-openjdk-amd64 | Image-provided JDK path (via `K8sPaths.jdk`) |
| Tmp | /tmp | Temporary directory |
| Bin | /usr/share/opensearch/bin | Executables |
| Certs | /etc/opensearch/certificates | TLS certificates |

### VM Paths
Uses snap-specific paths:

| Path Type | VM Path | Notes |
|-----------|--------|-------|
| Home | /var/snap/opensearch/current/usr/share/opensearch | Snap data (`/var/snap/opensearch/current`) + `usr/share/opensearch` |
| Config | /var/snap/opensearch/current/etc/opensearch | Snap data + `etc/opensearch` |
| Data | /var/snap/opensearch/common/var/lib/opensearch | Snap common (`/var/snap/opensearch/common`) + `var/lib/opensearch` |
| Logs | /var/snap/opensearch/common/var/log/opensearch | Snap common + `var/log/opensearch` |
| JDK | /snap/opensearch/current/usr/lib/jvm/java-21-openjdk-amd64 | From `workload.paths.jdk` |
| Tmp | /var/snap/opensearch/common/usr/share/tmp | From `workload.paths.tmp` |
| Bin | /snap/opensearch/current/usr/share/opensearch/bin | From `workload.paths.bin` |
| Certs | /var/snap/opensearch/current/etc/opensearch/certificates | `workload.paths.certs` |



## 3. Node Configuration

### Node Name (node.name)

K8s:
```python
node_name = socket.gethostname()
```
- Reason: OpenSearch uses the container hostname by default, using the same value avoids bootstrap mismatches.
- Critical: Must match what the node reports as its name at runtime or bootstrap can fail.
- Example: `opensearch-0`, `opensearch-1`

VM:
```python
node_name = unit_name
```
- Reason: On VM, the charm uses Juju unit name as a stable identifier for `node.name`.
- Note: Unlike K8s, OpenSearch does not require `node.name` to equal the OS hostname, it just needs to be consistent within the cluster.
- Example: `opensearch/0`, `opensearch/1`


### Bootstrap Configuration (cluster.initial_cluster_manager_nodes)

K8s:
```python
# Uses hostname for bootstrap (matches node.name)
bootstrap_cm_names = [node_name]  
```
- Critical: Must use the same naming scheme as `node.name` (hostname on K8s), not Juju unit name.
- Failure: ClusterManagerNotDiscoveredException if names don't match

VM:
```python
# Uses unit names as-is
bootstrap_cm_names = cm_names  
```
- Reason: Uses Juju unit names (same scheme as VM `node.name` in this charm).


## 4. Network Configuration

### Network Hosts

K8s (initial node config):
```yaml
network.host: ["_site_", "_local_", ...]
```
- _site_: Binds to pod IP for external access via Kubernetes Service
- _local_: Binds to localhost for Pebble health checks and internal monitoring
- Both required: Pod IP for external access, localhost for health checks

VM:
```yaml
network.host: ["_site_", "_local_", ...]
```
- _site_: Binds to network interface
- Note: The charm's initial `set_node()` currently prepends `["_site_", "_local_"]` even on VM, but subsequent `update_host_if_needed()` may rewrite the value without `_local_`.


### Publish Host (http.publish_host)

K8s:
```python
# Prefer a stable name when available, fall back if container is not connectable yet
public_address = self.workload.get_host_public_ip() or self.state.network_ingress_address
```
- Returns: Typically a pod DNS name when the container is connectable, otherwise falls back to an ingress/known address.
- Reason: Pod IPs are ephemeral, a stable name is better for TLS SANs and clients.

VM:
```python
public_address = self.workload.get_host_public_ip() or self.state.network_ingress_address
```
- Returns: Usually an IP address, with a fallback to ingress/known address.


### Security Admin Host (securityadmin.sh -h)

K8s:
```python
securityadmin_host = self.workload.get_host_public_ip() or self.state.host_ip
```

VM:
```python
securityadmin_host = self.workload.get_host_public_ip() or self.state.host_ip
```


## 5. Service Management

### Service Start/Stop

K8s:
```python
# Pebble service management
container.pebble.start_service("opensearch")
container.pebble.stop_service("opensearch")
container.pebble.restart_service("opensearch")
```
- Service Name: opensearch
- Management: Via Pebble API

VM:
```python
# Snap service management
snap.start(["daemon"])
snap.stop(["daemon"])
```
- Service Name: opensearch.daemon
- Management: Via snap API


### Service Status Check

K8s:
```python
# Checks Pebble service status
container.pebble.get_service("opensearch").current == ServiceStatus.ACTIVE
```

VM:
```python
# Checks systemd service status
service_running("snap.opensearch.daemon.service")
# Also checks JVM process via lsof
pid = run_cmd("lsof", args="-ti:9200")
```


## 6. File Operations

### File Path Types

K8s:
```python
# Uses ContainerPath (pathops library)
from charmlibs.pathops import ContainerPath
path = ContainerPath(container, "/etc/opensearch/opensearch.yml")
content = path.read_text()  # Internally calls container.pull()
path.write_text(content)   # Internally calls container.push()
```
- Requires: Container connection (container.can_connect)
- Operations: Pull/push via Pebble API
- Abstraction: pathops library handles container operations

VM:
```python
# Uses LocalPath (pathops library)
from charmlibs.pathops import LocalPath
path = LocalPath("/var/snap/opensearch/current/etc/opensearch/opensearch.yml")
content = path.read_text()  # Direct filesystem read
path.write_text(content)    # Direct filesystem write
```
- Requires: Direct filesystem access
- Operations: Standard file I/O
- Abstraction: pathops library handles local operations


### Container Readiness Check

K8s:
```python
# Must check container readiness before file operations
if self.state.substrate == Substrates.K8S and not self.workload.workload_present:
    raise ContainerNotReadyError("Container is not ready for filesystem operations")
```

VM:
```python
# No container check needed
# Direct filesystem access always available
```


## 7. System Requirements

### Kernel Parameters (sysctls)

K8s:
```python
# we expect that sysctls are arranged externally.
```

VM:
```python
# Configured via sysctl command
run_cmd(f"sysctl -w {system_requirement}={value}")
```
- Method: Direct sysctl command execution
- Parameters: Same as K8s
- Timing: During system requirement checks


## 8. Container/Workload Readiness

### Workload Present Check

K8s:
```python
@property
def workload_present(self) -> bool:
    """Check if container is ready and connected."""
    try:
        container = self.container
        return container.can_connect()
    except (RuntimeError, ModelError):
        return False
```
- Checks: Container connection via Pebble
- Required: Before any file operations

VM:
```python
@property
def workload_present(self) -> bool:
    """Check if the snap is installed."""
    try:
        return self.opensearch_snap.present
    except (snap.SnapError, AttributeError):
        return False
```
- Checks: Snap installation status
- Required: Before service operations


### Event Deferral

K8s:
```python
# Defer events if container not ready
if self.state.substrate == Substrates.K8S:
    if not self.workload.workload_present:
        logger.info("Container not ready for config-changed event, deferring")
        event.defer()
        return
```

VM:
```python
# No container readiness check needed
# Events proceed normally
```


## 9. Certificate Handling

### Certificate Path Access

K8s:
```python
# May need to pull certificates from container
# Cache certificates in charm container for verification
def _get_chain_pem_path(self) -> str | bool:
    try:
        container = self.workload.container
    except AttributeError:
        # VM substrate
        return chain_path_str

    # For K8s, check cache first
    if self._chain_pem_cache_path and os.path.exists(self._chain_pem_cache_path):
        return self._chain_pem_cache_path

    # Pull from container and cache (or return False if not available yet)
    return self._pull_and_cache_chain_pem(chain_path_str)
```
- Challenge: Charm container needs certificates from workload container
- Solution: Pull and cache certificates in charm container
- Cache Location: `/tmp/opensearch-certs/chain.pem` in charm container
- Failure mode: returns `False` to temporarily disable TLS verification until `chain.pem` is available

VM:
```python
# Direct filesystem access
# No caching needed
def _get_chain_pem_path(self) -> str | bool:
    # VM substrate, return direct filesystem path
    return chain_path_str
```
- Access: Direct filesystem read when present, returns `False` (disable verification) if missing.


### Certificate File Operations

K8s:
```python
# Uses pathops ContainerPath
chain_path = self.workload.paths.certs / "chain.pem"
chain_content = chain_path.read_text()  # Pulls from container
```
- Operation: container.pull via pathops abstraction

VM:
```python
# Uses pathops LocalPath
chain_path = self.workload.paths.certs / "chain.pem"
chain_content = chain_path.read_text()  # Direct read
```
- Operation: Standard file read


## 10. Event Handling

### Install Event

K8s:
```python
# K8s: container preparation is handled in pebble-ready.
if self.charm.state.substrate == Substrates.K8S:
    return
```

VM:
```python
# Install snap package
self.charm.workload.install()
```


### Config Changed Event

K8s:
```python
# Check container readiness
if self.state.substrate == Substrates.K8S:
    if not self.workload.workload_present:
        event.defer()
        return
```

VM:
```python
# No container check needed
# Proceed with config updates
```

### Start Event

K8s:
```python
# K8s: start may defer until pebble-ready + container preparation complete.
```

VM:
```python
# Handle host reboot scenario
if self.charm.state.substrate == Substrates.VM:
    if self.charm.cluster_manager.needs_start_after_host_reboot:
        # Restart service after host reboot
```


## 11. Changes in Managers and Event Handlers

### Config Manager (managers/config.py)

Handles OpenSearch configuration file management:

- set_node
  - Node name configuration (K8s: hostname, VM: unit_name)
  - Bootstrap configuration (K8s: hostname, VM: unit_names)
  - Network host configuration (includes _local_ for K8s)
  - Path configuration (appends /data and /logs for K8s)

- update_host_if_needed
  - Container readiness check for K8s
  - Network host updates

### Cluster Manager (managers/cluster.py)

Handles cluster operations and security initialization:

- _initialize_security_index
  - Security admin host selection: `workload.get_host_public_ip() or state.host_ip`

### TLS Manager (managers/tls.py)

Handles TLS artifacts (keys/certs/PKCS12), permissions, and CA rotation.

- Keytool command selection
  - K8s: uses the image JDK path (via `workload.paths.jdk`, which is `/usr/lib/jvm/java-21-openjdk-amd64`) for deterministic `keytool` usage.
  - VM: uses the snap JDK path (`/snap/opensearch/current/usr/lib/jvm/java-21-openjdk-amd64/bin/keytool` via `workload.paths.jdk`).

- Certificates directory creation (`_ensure_certificates_directory`)
  - K8s: uses Pebble file API (`container.exists` / `container.make_dir`) and falls back to exec (`mkdir/chmod`) if needed, guarded by `container.can_connect()`.
  - VM: uses local filesystem `mkdir` via pathops (no Pebble container).

- Permissions / ownership
  - K8s: runs `chmod 640 ...` (no sudo) and may chown to the rock image UID/GID.
  - VM: runs `sudo chmod 640 ...` (and other sudo-based ops where needed).


### Common Client (common/client.py)

Handles HTTP client operations and certificate access:

- _get_chain_pem_path
  - Substrate detection via try-except AttributeError
  - Certificate caching for K8s (pulls from container)
  - Direct filesystem access for VM

- _pull_and_cache_chain_pem
  - Certificate pull and cache logic for K8s

### Event Handlers (events/opensearch.py)

Handle Juju events with substrate-specific logic:

- _on_install
  - K8s: no-op (container preparation happens in `pebble-ready`)
  - VM: installs via `workload.install()`

- _on_config_changed
  - K8s: container readiness check (defers if not connectable yet)
  - VM: Direct config updates
  - Calls config_manager.update_host_if_needed

- _on_start
  - K8s: may defer (via underlying managers) until container is ready
  - VM: handles host reboot scenario (if applicable)

### Workload Implementations

#### K8s Workload (workload/k8s.py)

- K8sPaths class: Standard Linux paths
- K8sWorkload class
  - workload_present property: Container connection check
  - get_host_public_ip method: Returns DNS name
  - start_service_only method: Pebble service start
  - stop method: Pebble service stop
  - is_service_started method: Pebble service status check

#### VM Workload (workload/vm.py)

- VMWorkload class
  - workload_present property: Snap installation check
  - get_host_public_ip method: Returns IP address
  - install method: Snap installation
  - start_service_only method: Snap service start
  - stop method: Snap service stop
  - is_service_started method: Systemd + JVM process check
  - _apply_system_requirement method: Sysctl command execution

#### Base Workload (workload/base.py)

- BaseWorkload abstract class: Common interface
- Paths class: VM snap paths
- write_text method: Polymorphic file write
- read_text method: Polymorphic file read

### Charm Implementation (charms/k8s.py)

K8s-specific charm logic:

- Creates `K8sWorkload` with a `container_getter` so managers can check readiness (`workload_present`)
- Defers container preparation to the `pebble-ready` event via `workload.prepare_for_pebble_ready()`
