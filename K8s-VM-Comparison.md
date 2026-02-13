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



## Workload Implementation

### K8s
- Class: K8sWorkload (workload/k8s.py)
- Runtime: Pebble (container orchestration)
- Container: Uses ops.Container for container operations
- Service: Pebble service (opensearch)
- Image: Rock image (Ubuntu-based container image)

Code Location:
- Component: Workload Implementation
- File: workload/k8s.py
- Class: K8sWorkload
- Methods: __init__, workload_present property, container property

### VM
- Class: VMWorkload (workload/vm.py)
- Runtime: Snap (Ubuntu snap package)
- Container: N/A (direct filesystem access)
- Service: Snap service (opensearch.daemon)
- Package: Snap package (opensearch)

Code Location:
- Component: Workload Implementation
- File: workload/vm.py
- Class: VMWorkload
- Methods: __init__, workload_present property



## File System Paths

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


Code Location:
- Component: Config Manager
- File: managers/config.py
- Method: set_node
- Logic: Checks for K8s paths and appends /data and /logs subdirectories

Special Handling: 
- K8s requires /data and /logs subdirectories to be appended to paths
- VM paths are already structured correctly via snap

Path Implementation:
- K8s: workload/k8s.py - K8sPaths class
- VM: workload/base.py - Paths class



## Node Configuration

### Node Name (node.name)

K8s:
```python
# Uses container hostname (e.g., "opensearch-0")
node_name = socket.gethostname()
```
- Reason: OpenSearch uses hostname by default in containers
- Critical: Must match container hostname or bootstrap fails
- Example: opensearch-0, opensearch-1

VM:
```python
# Uses Juju unit name (e.g., "opensearch/0")
node_name = unit_name
```
- Reason: Unit name matches hostname on VM
- Example: opensearch/0, opensearch/1

Code Location:
- Component: Config Manager
- File: managers/config.py
- Method: set_node
- Logic: Substrate check determines whether to use hostname (K8s) or unit_name (VM)

### Bootstrap Configuration (cluster.initial_cluster_manager_nodes)

K8s:
```python
# Uses hostname for bootstrap (matches node.name)
bootstrap_cm_names = [node_name]  # e.g., ["opensearch-0"]
```
- Critical: Must use hostname, not unit_name
- Failure: ClusterManagerNotDiscoveredException if names don't match

VM:
```python
# Uses unit names as-is
bootstrap_cm_names = cm_names  # e.g., ["opensearch/0"]
```
- Reason: Unit name matches hostname on VM

Code Location:
- Component: Config Manager
- File: managers/config.py
- Method: set_node
- Logic: Substrate check determines bootstrap names (hostname for K8s, unit names for VM)


## Network Configuration

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

Code Location:
- Component: Config Manager
- File: managers/config.py
- Method: set_node
- Note: _local_ is always included in the list, but only relevant for K8s

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

Code Location:
- Component: Config Manager
- File: managers/config.py
- Method: set_node
- Implementation: workload.get_host_public_ip returns DNS name for K8s, IP for VM
  - K8s: workload/k8s.py - get_host_public_ip method
  - VM: workload/vm.py - get_host_public_ip method

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

Code Location:
- Component: Cluster Manager
- File: managers/cluster.py
- Method: _initialize_security_index
- Logic: Uses workload.get_host_public_ip for K8s (DNS), falls back to state.host_ip for VM (IP)

## Service Management

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

Code Location:
- Component: Workload Implementation
- K8s: workload/k8s.py - start_service_only method, stop method
- VM: workload/vm.py - start_service_only method, stop method

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

Code Location:
- Component: Workload Implementation
- K8s: workload/k8s.py - is_service_started method
- VM: workload/vm.py - is_service_started method


## File Operations

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

Code Location:
- Component: Workload Implementation (Base Interface)
- File: workload/base.py
- Methods: write_text, read_text
- Implementation: Polymorphic - pathops library handles substrate differences
  - K8s: Uses ContainerPath (automatically pulls/pushes)
  - VM: Uses LocalPath (direct filesystem access)

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

Code Location:
- Component: Config Manager
- File: managers/config.py
- Method: update_host_if_needed
- Logic: Only checks container readiness for K8s substrate

## System Requirements

### Kernel Parameters (sysctls)

K8s:
```python
# Configured via StatefulSet patch (JSON Patch)
# Applied during pod creation/update
configure_pod_sysctls()  # Patches StatefulSet with sysctls
```
- Method: JSON Patch to StatefulSet spec
- Location: charms/k8s.py - configure_pod_sysctls method
- Parameters: vm.max_map_count, vm.swappiness, net.ipv4.tcp_retries2
- Timing: During install, config-changed, and start events

VM:
```python
# Configured via sysctl command
run_cmd(f"sysctl -w {system_requirement}={value}")
```
- Method: Direct sysctl command execution
- Parameters: Same as K8s
- Timing: During system requirement checks

Code Location:
- Component: Charm (K8s) / Workload (VM)
- K8s: charms/k8s.py - configure_pod_sysctls method
- VM: workload/vm.py - _apply_system_requirement method
- Event Handler: events/opensearch.py
  - _on_install - calls configure_pod_sysctls for K8s
  - _on_config_changed - calls configure_pod_sysctls for K8s
  - _on_start - calls configure_pod_sysctls for K8s


## Container/Workload Readiness

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

Code Location:
- Component: Workload Implementation
- K8s: workload/k8s.py - workload_present property
- VM: workload/vm.py - workload_present property

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

Code Location:
- Component: Event Handler
- File: events/opensearch.py
- Method: _on_config_changed
- Logic: Only defers events for K8s if container not ready

## Certificate Handling

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

Code Location:
- Component: Common Client
- File: common/client.py
- Method: _get_chain_pem_path
- Logic: Substrate detection via try-except AttributeError to check for container attribute

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

Code Location:
- Component: Common Client
- File: common/client.py
- Method: _pull_and_cache_chain_pem
- Implementation: Uses pathops abstraction - ContainerPath.read_text for K8s, LocalPath.read_text for VM

## Event Handling

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

Code Location:
- Component: Event Handler
- File: events/opensearch.py
- Method: _on_config_changed
- K8s Logic: Checks container readiness, configures sysctls
- VM Logic: Proceeds directly with config updates
- Config Manager: Calls config_manager.update_host_if_needed

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

Code Location:
- Component: Event Handler
- File: events/opensearch.py
- Method: _on_start
- K8s Logic: Ensures pod sysctls configured
- VM Logic: Handles host reboot scenario (pods don't have host reboots)


## Component Reference

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

