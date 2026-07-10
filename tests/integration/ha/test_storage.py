#!/usr/bin/env python3
# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

import logging
import subprocess
import time

import jubilant
import pytest

from tests.integration.conftest import (
    APP_NAME,
    CONFIG_OPTS,
    MODEL_CONFIG,
)
from tests.integration.ha.continuous_writes import ContinuousWrites
from tests.integration.ha.helpers import (
    assert_continuous_writes_increasing,
    storage_id,
    storage_type,
)
from tests.integration.ha.test_horizontal_scaling import IDLE_PERIOD
from tests.integration.helpers import (
    EmptyActiveStatus,
    EmptyBlockedStatus,
    _series_to_base,
    app_name,
    get_application_unit_ids,
    wait_until,
)
from tests.integration.tls.conftest import TLS_CERTIFICATES_APP_NAME, TLS_STABLE_CHANNEL

logger = logging.getLogger(__name__)


@pytest.mark.abort_on_fail
@pytest.mark.skip_if_substrate("k8s")
async def test_build_and_deploy(juju: jubilant.Juju, charm, series) -> None:
    """Build and deploy one unit of OpenSearch."""
    # it is possible for users to provide their own cluster for HA testing.
    # Hence, check if there is a pre-existing cluster.
    if await app_name(juju):
        return

    juju.model_config(MODEL_CONFIG)
    # this assumes the test is run on a lxd cloud
    juju.cli("create-storage-pool", "opensearch-pool", "lxd")
    storage = {"opensearch-data": {"pool": "opensearch-pool", "size": 2048}}
    # Deploy TLS Certificates operator.
    config = {"ca-common-name": "CN_CA"}
    juju.deploy(TLS_CERTIFICATES_APP_NAME, channel=TLS_STABLE_CHANNEL, config=config)
    juju.deploy(
        charm,
        app=APP_NAME,
        num_units=1,
        base=_series_to_base(series),
        storage=storage,
        config=CONFIG_OPTS,
    )

    # Relate it to OpenSearch to set up TLS.
    juju.integrate(APP_NAME, TLS_CERTIFICATES_APP_NAME)
    await wait_until(
        juju,
        apps=[TLS_CERTIFICATES_APP_NAME, APP_NAME],
        timeout=1000,
        idle_period=IDLE_PERIOD,
        wait_for_exact_units={
            TLS_CERTIFICATES_APP_NAME: 1,
            "opensearch": 1,
        },
    )
    assert len(juju.status().apps[APP_NAME].units) == 1


@pytest.mark.abort_on_fail
async def test_storage_reuse_after_scale_down(
    juju: jubilant.Juju, c_writes: ContinuousWrites, c_writes_runner
):
    """Check storage is reused and data accessible after scaling down and up."""
    app = (await app_name(juju)) or APP_NAME

    if storage_type(juju, app) == "rootfs":
        pytest.skip(
            "reuse of storage can only be used on deployments with persistent storage not on rootfs deployments"
        )

    # scale up to 2 units
    juju.add_unit(app, num_units=1)
    await wait_until(
        juju,
        apps=[app],
        timeout=1000,
        idle_period=IDLE_PERIOD,
        wait_for_exact_units={
            app: 2,
        },
    )

    writes_result = await c_writes.stop()

    # get unit info
    unit_id = get_application_unit_ids(juju, app)[1]
    unit_storage_id = storage_id(juju, app, unit_id)

    # create a testfile on the newly added unit to check if data in storage is persistent
    testfile = "/var/snap/opensearch/common/testfile"
    create_testfile_cmd = f"juju ssh {app}/{unit_id} -q sudo touch {testfile}"
    subprocess.run(create_testfile_cmd, shell=True)

    # scale-down to 1
    # app status might be blocked because after scaling down not all shards are assigned
    juju.remove_unit(f"{app}/{unit_id}")
    await wait_until(
        juju,
        apps=[app],
        apps_statuses={app: [EmptyActiveStatus, EmptyBlockedStatus]},
        timeout=1000,
        idle_period=IDLE_PERIOD,
        wait_for_exact_units={
            app: 1,
        },
    )

    # add unit with storage attached
    add_unit_cmd = f"add-unit {app} --model={juju.model} --attach-storage={unit_storage_id}"
    juju.cli(*add_unit_cmd.split())

    await wait_until(
        juju,
        apps=[app],
        timeout=1000,
        idle_period=IDLE_PERIOD,
        wait_for_exact_units={
            app: 2,
        },
    )

    # check the storage of the new unit
    new_unit_id = get_application_unit_ids(juju, app)[1]
    new_unit_storage_id = storage_id(juju, app, new_unit_id)
    assert unit_storage_id == new_unit_storage_id, "Storage IDs mismatch."

    # check if data is also imported
    assert writes_result.count == (await c_writes.count())
    assert writes_result.max_stored_id == (await c_writes.max_stored_id())

    # check if the testfile is still there or was overwritten on installation
    check_testfile_cmd = f"juju ssh {app}/{new_unit_id} -q sudo ls {testfile}"
    assert testfile == subprocess.getoutput(check_testfile_cmd)


@pytest.mark.abort_on_fail
async def test_storage_reuse_after_scale_to_zero(
    juju: jubilant.Juju, c_writes: ContinuousWrites, c_writes_runner
):
    """Check storage is reused and data accessible after scaling down and up."""
    app = (await app_name(juju)) or APP_NAME

    if storage_type(juju, app) == "rootfs":
        pytest.skip(
            "reuse of storage can only be used on deployments with persistent storage not on rootfs deployments"
        )

    writes_result = await c_writes.stop()

    # scale down to zero units in reverse order
    unit_ids = get_application_unit_ids(juju, app)
    storage_ids = {}
    for unit_id in unit_ids[::-1]:
        storage_ids[unit_id] = storage_id(juju, app, unit_id)
        juju.remove_unit(f"{app}/{unit_id}")
        # give some time for removing each unit
        time.sleep(60)

    # using wait_until doesn't really work well here with 0 units
    await wait_until(
        juju,
        apps=[app],
        timeout=1000,
        wait_for_exact_units=0,
    )

    # scale up again
    for unit_id in unit_ids:
        add_unit_cmd = (
            f"add-unit {app} --model={juju.model} --attach-storage={storage_ids[unit_id]}"
        )
        juju.cli(*add_unit_cmd.split())
        await wait_until(juju, apps=[app], timeout=1000)

    await wait_until(
        juju,
        apps=[app],
        timeout=1000,
        idle_period=IDLE_PERIOD,
        wait_for_exact_units={
            app: len(unit_ids),
        },
    )

    # check if data is also imported
    assert writes_result.count == (await c_writes.count())
    assert writes_result.max_stored_id == (await c_writes.max_stored_id())

    # restart continuous writes and check if they can be written
    await c_writes.start()
    time.sleep(30)
    await assert_continuous_writes_increasing(c_writes)


@pytest.mark.abort_on_fail
async def test_storage_reuse_in_new_cluster_after_app_removal(
    juju: jubilant.Juju, charm, c_writes: ContinuousWrites, c_balanced_writes_runner
):
    """Check storage is reused and data accessible after removing app and deploying new cluster."""
    app = (await app_name(juju)) or APP_NAME

    if storage_type(juju, app) == "rootfs":
        pytest.skip(
            "reuse of storage can only be used on deployments with persistent storage not on rootfs deployments"
        )

    # scale-up to 3 to make it a cluster
    unit_ids = get_application_unit_ids(juju, app)
    if len(unit_ids) < 3:
        juju.add_unit(app, num_units=3 - len(unit_ids))

        await wait_until(
            juju,
            apps=[app],
            timeout=1000,
            idle_period=IDLE_PERIOD,
            wait_for_exact_units={
                app: 3,
            },
        )
    else:
        # wait for enough data to be written
        time.sleep(60)

    writes_result = await c_writes.stop()

    # Scale down carefully to be able to identify which storage needs to be deployed to
    # the leader when scaling up again. This is to avoid stale metadata when reusing the
    # storage on a different cluster.
    storage_ids = []
    unit_ids = get_application_unit_ids(juju, app)

    # remember the current storage disks
    for unit_id in unit_ids:
        storage_ids.append(storage_id(juju, app, unit_id))

    # remove all but the first unit
    # this will trigger the remaining unit to become the leader if it wasn't already
    for unit_id in unit_ids[1:]:
        juju.remove_unit(f"{app}/{unit_id}")

    # app status might be blocked because after scaling down not all shards are assigned
    await wait_until(
        juju,
        apps=[app],
        apps_statuses={app: [EmptyActiveStatus, EmptyBlockedStatus]},
        timeout=1000,
        wait_for_exact_units={
            app: 1,
        },
    )

    # remove the remaining unit and the entire application
    juju.remove_application(app, destroy_storage=False)

    # deploy new cluster, attaching the storage from the previous leader to the new leader
    deploy_cluster_with_storage_cmd = (
        f"deploy {charm} --model={juju.model} --attach-storage={storage_ids[0]}"
        " --config profile=testing"
    )
    juju.cli(*deploy_cluster_with_storage_cmd.split())
    juju.integrate(app, TLS_CERTIFICATES_APP_NAME)

    # wait for cluster to be deployed
    # app status might be blocked because not all shards are assigned
    await wait_until(
        juju,
        apps=[app],
        apps_statuses={app: [EmptyActiveStatus, EmptyBlockedStatus]},
        wait_for_exact_units=1,
        timeout=2400,
    )

    # add unit with storage attached
    for unit_storage_id in storage_ids[1:]:
        add_unit_cmd = f"add-unit {app} --model={juju.model} --attach-storage={unit_storage_id}"
        juju.cli(*add_unit_cmd.split())

    # wait for new cluster to settle down
    await wait_until(
        juju,
        apps=[app],
        wait_for_exact_units=len(storage_ids),
        idle_period=IDLE_PERIOD,
        timeout=2400,
    )
    assert len(juju.status().apps[app].units) == len(storage_ids)

    # check if previous volumes are attached to the units of the new cluster
    new_storage_ids = []
    for unit_id in get_application_unit_ids(juju, app):
        new_storage_ids.append(storage_id(juju, app, unit_id))

    assert sorted(storage_ids) == sorted(new_storage_ids), "Storage IDs mismatch."

    # check if data is also imported
    assert writes_result.count == (await c_writes.count())
    assert writes_result.max_stored_id == (await c_writes.max_stored_id())

    # restart continuous writes and check if they can be written
    await c_writes.start()
    time.sleep(60)
    assert (await c_writes.count()) > 0, "Continuous writes not increasing"
