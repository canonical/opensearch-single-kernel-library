# OpenSearch Charms Single Kernel

Shared and reusable Python code for Canonical OpenSearch charms.

This repository contains the common implementation used by OpenSearch charms
across machine and Kubernetes substrates. It provides base charm classes,
workload abstractions, event handlers, state models, and managers for common
OpenSearch operations so charm-specific repositories can stay focused on their
substrate and packaging concerns.

The project is intended for contributors working on the OpenSearch charm codebase.

## What Is Included

- Base charm classes for VM and Kubernetes charms.
- Workload adapters for substrate-specific OpenSearch operations.
- Managers for cluster health, configuration, TLS, users, snapshots, plugins,
  upgrades, profiles, peer clusters, notifications, external clients, and locks.
- Event handlers for OpenSearch lifecycle events and supported Juju relations.
- Pydantic models and state helpers for relation data and cluster state.
- Vendored charm libraries required by the shared implementation.
- Test charms and integration fixtures used to validate the shared library.

## Repository Layout

| Path                                   | Purpose                                                               |
| -------------------------------------- | --------------------------------------------------------------------- |
| `opensearch_single_kernel/charms/`     | Base charm classes and VM/Kubernetes charm entry points.              |
| `opensearch_single_kernel/workload/`   | Workload abstractions and substrate-specific implementations.         |
| `opensearch_single_kernel/managers/`   | Operational managers for OpenSearch features and lifecycle work.      |
| `opensearch_single_kernel/events/`     | Juju event handlers and custom OpenSearch events.                     |
| `opensearch_single_kernel/core/`       | Relation state, secrets, models, and shared data structures.          |
| `opensearch_single_kernel/common/`     | Constants, statuses, exceptions, and the OpenSearch client.           |
| `opensearch_single_kernel/lib/`        | Vendored charm libraries refreshed through charmcraft.                |
| `tests/unit/`                          | Unit tests for the shared library.                                    |
| `tests/integration/`                   | Integration tests and supporting charms.                              |
| `tests/charms/`                        | Local test charms that consume the shared kernel.                     |
| `scripts/build_lib_for_integration.sh` | Helper for copying the local library into test charms before packing. |

## Development

Install `tox` and `poetry` with `pipx`:

```shell
pipx install tox
pipx install poetry
```

Install the project dependencies:

```shell
poetry install
```

Install pre-commit hooks before submitting changes:

```shell
poetry run pre-commit install
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for contribution guidelines and the
Canonical contributor agreement.

## Testing

Run the default local checks:

```shell
tox
```

Useful tox environments:

```shell
tox run -e format       # apply formatting
tox run -e lint         # lint, spelling, formatting, and shell checks
tox run -e unit         # unit tests for all substrates
tox run -e unit-vm      # unit tests with the VM substrate
tox run -e unit-k8s     # unit tests with the Kubernetes substrate
tox run -e integration  # integration tests
tox run -e build        # build the Python package
```

Integration tests require a Juju test environment and, for object storage
scenarios, the cloud credentials consumed by `tox.ini`.

## Building Test Charms for Integration Runs

Use `scripts/build_lib_for_integration.sh` when an integration run needs test
charms packed with the local version of this library:

```shell
scripts/build_lib_for_integration.sh
```

By default, the script prepares `tests/charms/opensearch_test_charm`. You can
target another charm and, when needed, pass a charmcraft platform:

```shell
scripts/build_lib_for_integration.sh --charm tests/charms/opensearch_k8s_test_charm
scripts/build_lib_for_integration.sh --platform amd64 --charm tests/charms/opensearch_test_charm
```

## Project Links

- Homepage: <https://github.com/canonical/opensearch-single-kernel-library>
- Issues: <https://github.com/canonical/opensearch-single-kernel-library/issues>
- Contributing: [CONTRIBUTING.md](CONTRIBUTING.md)
- License: [Apache-2.0](LICENSE)
