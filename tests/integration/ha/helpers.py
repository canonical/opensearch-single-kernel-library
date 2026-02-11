#!/usr/bin/env python3
# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

import asyncio
import logging
from typing import List

from pytest_operator.plugin import OpsTest
from tenacity import retry, stop_after_attempt, wait_fixed, wait_random

from tests.integration.helpers import (
    get_application_unit_ids_ips,
    get_leader_unit_ip,
    http_request,
)
from tests.integration.models import Shard

from .continuous_writes import ContinuousWrites

logger = logging.getLogger(__name__)


@retry(
    wait=wait_fixed(wait=15) + wait_random(0, 5),
    stop=stop_after_attempt(25),
)
async def get_shards_by_index(ops_test: OpsTest, unit_ip: str, index_name: str) -> List[Shard]:
    """Returns the list of shards and their location in cluster for an index.

    Args:
        ops_test: The ops test framework instance.
        unit_ip: The ip of the OpenSearch unit.
        index_name: the name of the index.

    Returns:
        List of shards.
    """
    response = await http_request(
        ops_test,
        "GET",
        f"https://{unit_ip}:9200/{index_name}/_search_shards",
    )

    nodes = response["nodes"]

    result = []
    for shards_collection in response["shards"]:
        for shard in shards_collection:
            node_name_split = nodes[shard["node"]]["name"].split(".")[0].split("-")
            result.append(
                Shard(
                    index=index_name,
                    num=shard["shard"],
                    is_prim=shard["primary"],
                    node_id=shard["node"],
                    unit_id=int(node_name_split[-1]),
                    app="-".join(node_name_split[:-1]),
                )
            )

    return result


async def assert_continuous_writes_increasing(
    c_writes: ContinuousWrites,
) -> None:
    """Asserts that the continuous writes are increasing."""
    writes_count = await c_writes.count()
    await asyncio.sleep(20)
    more_writes = await c_writes.count()
    assert more_writes > writes_count, "Writes not continuing to DB"


async def assert_continuous_writes_consistency(
    ops_test: OpsTest, c_writes: ContinuousWrites, apps: List[str]
) -> None:
    """Continuous writes checks."""
    result = await c_writes.stop()
    logger.info(f"Continuous writes result: {result}")
    assert result.max_stored_id == result.count - 1
    assert result.max_stored_id == result.last_expected_id

    unit_ip = await get_leader_unit_ip(ops_test, apps[0])

    # fetch unit ips by unit id by application
    apps_units_ips = {app: await get_application_unit_ids_ips(ops_test, app) for app in apps}

    # investigate the data in each shard, primaries and their respective replicas
    shards = await get_shards_by_index(ops_test, unit_ip, ContinuousWrites.INDEX_NAME)
    shards_by_id = {}
    for shard in shards:
        shards_by_id.setdefault(shard.num, []).append(shard)

    # count data on each shard. For the **balanced** continuous writes index, we have 2
    # primary shards and replica shards of each on all the nodes. In other words: prim1 and
    # its replicas will have a different "num" than prim2 and its replicas.
    count_from_shards = 0
    for shard_num, shards_list in shards_by_id.items():
        count_by_shard = [
            await c_writes.count(
                unit_ip=apps_units_ips[shard.app][shard.unit_id],
                preference=f"_shards:{shard_num}|_only_local",
            )
            for shard in shards_list
        ]
        # all shards with the same id must have the same count
        assert len(set(count_by_shard)) == 1
        count_from_shards += count_by_shard[0]

    assert result.count == count_from_shards
