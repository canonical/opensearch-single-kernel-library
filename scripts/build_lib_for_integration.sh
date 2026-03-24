#!/bin/bash

## This builds the whl and then copies it to test charms and updates their dependencies.

set -e

pack_charm() {
    if [ "${CI_CACHE:-false}" = "true" ] && command -v ccc >/dev/null 2>&1; then
        ccc pack -v
    else
        charmcraft pack -v
    fi
}

LIB_PATH="./opensearch_single_kernel"

CHARMS_PATH="./tests/charms"
THIRD_PARTY_CHARMS=("./tests/integration/relations/opensearch_provider/application-charm")

if [ $# -ge 1 ]; then
    declare -a TEST_CHARMS=("$1")
else
    # Build for both VM and K8s test charms
    declare -a TEST_CHARMS=(
        "${CHARMS_PATH}/opensearch_test_charm"
        "${CHARMS_PATH}/opensearch_k8s_test_charm"
    )
fi

for directory in "${TEST_CHARMS[@]}"; do
    if [[ " ${THIRD_PARTY_CHARMS[*]} " =~ ${directory} ]]; then
        echo "Packing third party charm ${directory}"
        pushd "$directory" >/dev/null
        pack_charm
        popd >/dev/null
        continue
    fi

    echo "Clearing out libs for charm ${directory}"
    directory_lib_path="${directory}/${LIB_PATH}"
    rm -rf "$directory_lib_path"
    mkdir -p "$directory_lib_path"

    echo "Copying over libs from single kernel charm"
    cp -r "${LIB_PATH}" "$directory_lib_path"
    # Copy pyproject.toml and README.md to the library directory as it is needed for poetry
    cp "pyproject.toml" "$directory_lib_path"
    cp "README.md" "$directory_lib_path"

    echo "Building charm ${directory}"
    pushd "$directory" >/dev/null

    # Backup files if they exist in the charm directory
    if [ -f pyproject.toml ]; then
        cp pyproject.toml pyproject.toml.backup
    fi
    if [ -f poetry.lock ]; then
        cp poetry.lock poetry.lock.backup
    fi

    # Disable strict mode for the copied test library.
    pushd "${LIB_PATH}" >/dev/null
    git init >/dev/null 2>&1
    sed -i 's/strict = true/strict = false/' "pyproject.toml"
    popd >/dev/null

    # Add library and lock dependencies if pyproject.toml exists in charm directory
    if [ -f pyproject.toml ]; then
        poetry add "${LIB_PATH}/"
        poetry lock
    else
        echo "Info: pyproject.toml not found in ${directory}, skipping poetry operations."
    fi

    # Update charm_version with git hash if charm_version file exists
    if [ -f charm_version ]; then
        python3 -c 'import pathlib, shutil, subprocess; git_hash = subprocess.run(["git", "describe", "--always", "--dirty"], capture_output=True, check=True, encoding="utf-8").stdout.strip(); file = pathlib.Path("charm_version"); shutil.copy(file, pathlib.Path("charm_version.backup")); version = file.read_text().strip(); file.write_text(f"{version}+{git_hash}")'
    fi

    # Pack the charm only if charmcraft.yaml exists
    if [ -f charmcraft.yaml ]; then
        pack_charm
    else
        echo "Info: charmcraft.yaml not found in ${directory}, skipping charm packing."
    fi

    echo "Removing copied files from single kernel charm."
    rm -rf "${LIB_PATH}"
    if [ -f charm_version.backup ]; then
        mv charm_version.backup charm_version
    fi
    if [ -f pyproject.toml.backup ]; then
        mv pyproject.toml.backup pyproject.toml
    fi
    if [ -f poetry.lock.backup ]; then
        mv poetry.lock.backup poetry.lock
    fi

    popd >/dev/null
done
