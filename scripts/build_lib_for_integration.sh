#!/bin/bash

## This builds the whl and then copies it to all 4 test charms and updates the requirements file.

set -e

# Helper function to avoid code duplication
pack_charm() {
    if ${CI_CACHE:-false}; then
        ccc pack -v
    else
        charmcraft pack -v
    fi
}

git_hash=$(git describe --always --dirty)

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



    echo "clearing out libs for charm"
    directory_lib_path="${directory}/${LIB_PATH}"
    rm -rf "$directory_lib_path"
    mkdir "$directory_lib_path"
    echo "copying over libs from single kernel charm"
    cp -r "${LIB_PATH}" "$directory_lib_path"
    # Copy pyproject.toml and README.md to the library directory as it is needed for poetry
    cp "pyproject.toml" "$directory_lib_path"
    cp "README.md" "$directory_lib_path"


    # Pack the third party charms
    if [[ " ${THIRD_PARTY_CHARMS[*]} " =~ ${directory} ]]; then
        echo "Packing third party charm ${directory}\n"
        pushd $directory
        pack_charm
        popd
    else
        echo "clearing out libs for charm"
        directory_lib_path="${directory}/${LIB_PATH}"
        rm -rf "$directory_lib_path"
        mkdir "$directory_lib_path"
        echo "copying over libs from single kernel charm"
        cp -r "${LIB_PATH}" "$directory_lib_path"
        cp "pyproject.toml" "$directory_lib_path"
        cp "README.md" "$directory_lib_path"

        echo "Building charm ${directory}\n"


        pushd $directory

        # Backup files
        cp pyproject.toml pyproject.toml.backup
        cp poetry.lock poetry.lock.backup
    # Backup files if they exist in the charm directory
    if [ -f pyproject.toml ]; then
        cp pyproject.toml pyproject.toml.backup
    fi
    if [ -f poetry.lock ]; then
        cp poetry.lock poetry.lock.backup
    fi

        # Disable strict mode for build test lib.
        pushd "${LIB_PATH}"
        git init
        sed 's/strict = true/strict = false/' -i "pyproject.toml"
        popd

        poetry add "${LIB_PATH}/"
        poetry lock
    # Add library and lock dependencies if pyproject.toml exists in charm directory
    if [ -f pyproject.toml ]; then
        poetry add "${LIB_PATH}/"
        poetry lock
    else
        echo "Info: pyproject.toml not found in ${directory}, skipping poetry operations (library copied but not added as dependency)"
    fi

        python3 -c 'import pathlib; import shutil; import subprocess; git_hash=subprocess.run(["git", "describe", "--always", "--dirty"], capture_output=True, check=True, encoding="utf-8").stdout; file = pathlib.Path("charm_version"); shutil.copy(file, pathlib.Path("charm_version.backup")); version = file.read_text().strip(); file.write_text(f"{version}+{git_hash}")'
    # Update charm_version with git hash if charm_version file exists
    if [ -f charm_version ]; then
        python3 -c 'import pathlib; import shutil; import subprocess; git_hash=subprocess.run(["git", "describe", "--always", "--dirty"], capture_output=True, check=True, encoding="utf-8").stdout; file = pathlib.Path("charm_version"); shutil.copy(file, pathlib.Path("charm_version.backup")); version = file.read_text().strip(); file.write_text(f"{version}+{git_hash}")'
    fi

        # Pack the charm
        pack_charm
    # Pack the charm only if charmcraft.yaml exists
    if [ -f charmcraft.yaml ]; then
        # Use ccc (charmcraft cache) if CI_CACHE is set and ccc command exists, otherwise use charmcraft
        if [ "${CI_CACHE:-false}" = "true" ] && command -v ccc >/dev/null 2>&1; then
            ccc pack -v
        else
            charmcraft pack -v
        fi
    else
        echo "Info: charmcraft.yaml not found in ${directory}, skipping charm packing (library copied successfully)"
    fi

        # Cleanup
        echo "removing copied files from single kernel charm."
        rm ${LIB_PATH} -rf
        mv charm_version.backup charm_version
        mv pyproject.toml.backup pyproject.toml
        mv poetry.lock.backup poetry.lock
    # Cleanup
    echo "removing copied files from single kernel charm."
    rm ${LIB_PATH} -rf
    if [ -f charm_version.backup ]; then
        mv charm_version.backup charm_version
    fi
    if [ -f pyproject.toml.backup ]; then
        mv pyproject.toml.backup pyproject.toml
    fi
    if [ -f poetry.lock.backup ]; then
        mv poetry.lock.backup poetry.lock
    fi

        # Go back to root directory
        popd
    fi
done
