
## Developing

Install `tox` and `poetry`

Install pipx: [https://pipx.pypa.io/stable/installation/](https://pipx.pypa.io/stable/installation/)

```shell
pipx install tox
pipx install poetry
```

You can create an environment for development:

```shell
poetry install
```

### Testing

```shell
tox run -e format        # update your code according to linting rules
tox run -e lint          # code style
tox run -e unit          # unit tests (defaults to VM substrate)
tox run -e unit-vm       # unit tests (VM substrate)
tox run -e unit-k8s      # unit tests (K8s substrate)
tox run -e integration   # integration tests
tox                      # runs 'lint' and 'unit' environments
```

### `pre-commit` hooks

This repository comes with a sensible [pre-commit](https://github.com/pre-commit/pre-commit) hook configuration.
Please install it with `pre-commit install` as this will be checked in the CI anyway.

### Development guidelines

We try to create each object at most once, at the highest level it's used:
We reduce the cost of object creation, and we also ensure that any variable
modification is kept and accessible from everywhere: For example the
Container object is created in the operator and then passed down to all
workload objects.

## Canonical Contributor Agreement

Canonical welcomes contributions to the OpenSearch Single Kernel Library.
check out our [contributor agreement](https://ubuntu.com/legal/contributors) if you're interested in contributing to the solution.
