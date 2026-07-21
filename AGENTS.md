This repository contains shared and reusable Python code for Canonical OpenSearch charms. It provides the common implementation used by OpenSearch charms across both machine (VM) and Kubernetes (K8s) substrates, allowing charm-specific repositories to focus on substrate and packaging concerns.

## Environment Setup
- Python 3.10
- Install Poetry: `pipx install poetry`
- Install Dependencies: `poetry install`
## Commands
### Build Charm
- When an integration run needs test charms packed with the local version of this library, use the build script:
  - Default target: `scripts/build_lib_for_integration.sh`
  - Target specific charms: `scripts/build_lib_for_integration.sh --charm tests/charms/opensearch_k8s_test_charm`
  - Specify architecture: `scripts/build_lib_for_integration.sh --platform amd64 --charm tests/charms/opensearch_test_charm`
### Build OpenSearch Charm (VM)
Run: `./scripts/build_lib_for_integration.sh`
### Build OpenSearch K8s Charm
Run: `./scripts/build_lib_for_integration.sh ./tests/charms/opensearch_k8s_test_charm/`
### Development & Test commands
- **Format code**: `tox run -e format`
- **Lint code**: `tox run -e lint` (Runs lints, spelling, formatting, and shell checks)
- **Unit tests (All)**: `tox run -e unit`
- **Unit tests (VM only)**: `tox run -e unit-vm`
- **Unit tests (K8s only)**: `tox run -e unit-k8s`
### Integration Testing Commands
- **Run integration tests**: `tox run -e integration`
- *Note* to run the integration tests an environment variable is needed `CHARM_UBUNTU_BASE=24.04` or `CHARM_UBUNTU_BASE=22.04`.
## Coding Conventions & Boundaries
- **Managers vs. Events**: Keep event handling (`events/`) distinct from operational execution and management (`managers/`).
- **State & Data**: Rely on Pydantic models and state helpers inside `core/` for relation data and cluster state.
- **Vendored Libraries**: The `opensearch_single_kernel/lib/` directory contains vendored charm libraries. **Do not modify these files directly**; they are exclusively managed and refreshed via `charmcraft`.
- **Dependencies**: Do not introduce new heavy dependencies in `pyproject.toml` without explicit user approval.
- **File Edits**: Default to small, focused diffs. Avoid repo-wide rewrites or broad refactoring unless explicitly instructed.
- **Substrate-Specific Code Boundaries**: All substrate-specific logic (code unique to either VMs or Kubernetes) MUST be confined exclusively to the **event handlers** (`events/`) or the **workload abstractions** (`workload/`). Shared modules must remain purely substrate-agnostic.
- **Manager Abstraction**: Operational managers (located in `managers/`) must be completely decoupled from the charm instance and event handlers. Managers should encapsulate pure OpenSearch operational logic and accept only the necessary state or objects as arguments, rather than relying on direct hooks into `CharmBase` or Juju events.
## Project Structure

```
opensearch_single_kernel/
├── charms/              # Charm base classes and substrate implementations
├── core/                # Pydantic models, state, and relation management
├── events/              # Event handlers for charm lifecycle and integrations
├── managers/            # Pure operational logic (substrate-agnostic)
├── workload/            # Substrate-specific workload abstractions
├── utils/               # Helper utilities
├── common/              # Shared constants and exceptions
└── lib/                 # Vendored charm libraries (do not modify)
```
