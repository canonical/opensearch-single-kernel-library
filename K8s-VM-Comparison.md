# K8s vs VM Substrate Comparison Guide

This document outlines the key differences between Kubernetes (K8s) and VM substrate implementations in the OpenSearch Single Kernel charm.

## Contents

1. Workload Implementation
2. File System Paths
3. Node Configuration
4. Network Configuration
5. Service Management
6. File Operations
7. System Requirements
8. Container/Workload Readiness
9. Certificate Handling
10. Event Handling



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
| Data | /var/lib/opensearch | Data directory (actual: /var/lib/opensearch/data) |
| Logs | /var/log/opensearch | Logs directory (actual: /var/log/opensearch/logs) |
| JDK | /usr/lib/jvm/java-21-openjdk-amd64 | Hardcoded JDK path |
| Tmp | /tmp | Temporary directory |
| Bin | /usr/share/opensearch/bin | Executables |
| Certs | /etc/opensearch/certificates | TLS certificates |

### VM Paths
Uses snap-specific paths:

| Path Type | VM Path | Notes |
|-----------|--------|-------|
| Home | /var/snap/opensearch/common/opensearch | Snap common data |
| Config | /var/snap/opensearch/common/opensearch/config | Configuration files |
| Data | /var/snap/opensearch/common/opensearch/data | Data directory |
| Logs | /var/snap/opensearch/common/opensearch/logs | Logs directory |
| JDK | /snap/opensearch/current/jdk | Snap revision-based |
| Tmp | /var/snap/opensearch/common/tmp | Temporary directory |
| Bin | /snap/opensearch/current/bin | Executables |
| Certs | /var/snap/opensearch/common/opensearch/config/certificates | TLS certificates |



## 3. Node Configuration

### Node Name (node.name)

K8s:
```python
node_name = socket.gethostname()
```
- Reason: OpenSearch uses hostname by default in containers
- Critical: Must match container hostname or bootstrap fails
- Example: opensearch-0, opensearch-1

VM:
```python
node_name = unit_name
```
- Reason: Unit name matches hostname on VM
- Example: opensearch/0, opensearch/1


### Bootstrap Configuration (cluster.initial_cluster_manager_nodes)

K8s:
```python
# Uses hostname for bootstrap (matches node.name)
bootstrap_cm_names = [node_name]  
```
- Critical: Must use hostname, not unit_name
- Failure: ClusterManagerNotDiscoveredException if names don't match

VM:
```python
# Uses unit names as-is
bootstrap_cm_names = cm_names  
```
- Reason: Unit name matches hostname on VM


## 4. Network Configuration

### Network Hosts

K8s:
```yaml
network.host: ["_site_", "_local_", ...]
```
- _site_: Binds to pod IP (for external access via Kubernetes Service)
- _local_: Binds to localhost (for Pebble health checks and internal monitoring)
- Both required: Pod IP for external access, localhost for health checks

VM:
```yaml
network.host: ["_site_", ...]
```
- _site_: Binds to network interface
- No _local_: Not needed for VM (no Pebble health checks)


### Publish Host (http.publish_host)

K8s:
```python
# Returns DNS name (stable, matches cert SANs)
public_address = self.workload.get_host_public_ip()  # e.g., "opensearch-0.opensearch-endpoints"
```
- Returns: DNS name (e.g., opensearch-0.opensearch-endpoints)
- Reason: Pod IPs are ephemeral, DNS names are stable
- Matches: Certificate SANs (Subject Alternative Names)

VM:
```python
# Returns IP address
public_address = self.workload.get_host_public_ip()
```
- Returns: IP address
- Reason: VMs have stable IP addresses


### Security Admin Host (securityadmin.sh -h)

K8s:
```python
# Uses DNS name (matches cert SANs)
securityadmin_host = self.workload.get_host_public_ip()
```

VM:
```python
# Uses IP address
securityadmin_host = self.state.host_ip  
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
path = LocalPath("/var/snap/opensearch/common/opensearch/config/opensearch.yml")
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
We expect that sysctls are arranged externally.

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
def _get_chain_pem_path(self) -> str:
    try:
        container = self.workload.container
    except AttributeError:
        # VM substrate
        return chain_path_str

    # For K8s, check cache first
    if self._chain_pem_cache_path and os.path.exists(self._chain_pem_cache_path):
        return self._chain_pem_cache_path

    # Pull from container and cache
    return self._pull_and_cache_chain_pem(chain_path_str)
```
- Challenge: Charm container needs certificates from workload container
- Solution: Pull and cache certificates in charm container
- Cache Location: `/tmp/chain.pem` in charm container

VM:
```python
# Direct filesystem access
# No caching needed
def _get_chain_pem_path(self) -> str:
    # VM substrate, return direct filesystem path
    return chain_path_str
```
- Access: Direct filesystem read
- No Caching: Not needed


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
# Configure pod sysctls via StatefulSet patch
if self.charm.state.substrate == Substrates.K8S:
    if hasattr(self.charm, 'configure_pod_sysctls'):
        self.charm.configure_pod_sysctls()
```

VM:
```python
# Install snap package
self.opensearch_snap.ensure(snap.SnapState.Latest, revision=OPENSEARCH_SNAP_REVISION)
```

Code Location:
- Component: Event Handler
- File: events/opensearch.py
- Method: _on_install
- K8s Logic: Calls configure_pod_sysctls if charm has the method
- VM Logic: Handled by workload.install method
  - VM: workload/vm.py - install method

### Config Changed Event

K8s:
```python
# Check container readiness
if self.state.substrate == Substrates.K8S:
    if not self.workload.workload_present:
        event.defer()
        return

    # Configure sysctls
    if hasattr(self.charm, 'configure_pod_sysctls'):
        self.charm.configure_pod_sysctls()
```

VM:
```python
# No container check needed
# Proceed with config updates
```

### Start Event

K8s:
```python
# Ensure pod sysctls configured
if self.charm.state.substrate == Substrates.K8S:
    if hasattr(self.charm, 'configure_pod_sysctls'):
        self.charm.configure_pod_sysctls()
```

VM:
```python
# Handle host reboot scenario
if self.charm.state.substrate == Substrates.VM:
    if self.charm.cluster_manager.needs_start_after_host_reboot:
        # Restart service after host reboot
```


## 11. Component Reference

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
  - Security admin host selection (K8s: DNS name, VM: IP address)
  - Uses workload.get_host_public_ip for K8s (DNS), falls back to state.host_ip for VM (IP)

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
  - K8s: Configures pod sysctls via configure_pod_sysctls
  - VM: Installs snap via workload.install

- _on_config_changed
  - K8s: Container readiness check and sysctl configuration
  - VM: Direct config updates
  - Calls config_manager.update_host_if_needed

- _on_start
  - K8s: Ensures pod sysctls configured
  - VM: Handles host reboot scenario

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

- configure_pod_sysctls method: StatefulSet JSON Patch for sysctls
- Called from event handlers: _on_install, _on_config_changed, _on_start
