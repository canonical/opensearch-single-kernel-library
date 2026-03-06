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
    declare -a TEST_CHARMS=("${CHARMS_PATH}/opensearch_test_charm" )
fi

for directory in "${TEST_CHARMS[@]}"; do

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

        # Disable strict mode for build test lib.
        pushd "${LIB_PATH}"
        git init
        sed 's/strict = true/strict = false/' -i "pyproject.toml"
        popd

        poetry add "${LIB_PATH}/"
        poetry lock

        python3 -c 'import pathlib; import shutil; import subprocess; git_hash=subprocess.run(["git", "describe", "--always", "--dirty"], capture_output=True, check=True, encoding="utf-8").stdout; file = pathlib.Path("charm_version"); shutil.copy(file, pathlib.Path("charm_version.backup")); version = file.read_text().strip(); file.write_text(f"{version}+{git_hash}")'

        # Pack the charm
        pack_charm

        # Cleanup
        echo "removing copied files from single kernel charm."
        rm ${LIB_PATH} -rf
        mv charm_version.backup charm_version
        mv pyproject.toml.backup pyproject.toml
        mv poetry.lock.backup poetry.lock

        # Go back to root directory
        popd
    fi
done
