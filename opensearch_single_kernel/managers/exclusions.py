#!/usr/bin/env python3
# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""OpenSearch Nodes Exclusions manager."""

import logging
from functools import cached_property

from opensearch_single_kernel.common.constants import Scope
from opensearch_single_kernel.common.exceptions import (
    OpenSearchExclusionsException,
    OpenSearchHttpError,
)
from opensearch_single_kernel.core.models import Node
from opensearch_single_kernel.core.state import ClusterState
from opensearch_single_kernel.managers.base import BaseManager
from opensearch_single_kernel.utils.helpers import format_unit_name
from opensearch_single_kernel.workload.base import BaseWorkload

logger = logging.getLogger(__name__)


class NodesExclusionsManager(BaseManager):
    """OpenSearch Nodes Exclusions Manager."""

    def __init__(self, state: ClusterState, workload: BaseWorkload):
        super().__init__(state, workload, "exclusions_manager")

    def add_current(
        self,
        scope: Scope,
        voting: bool = True,
        allocation: bool = True,
        raise_error: bool = False,
    ) -> None:
        """Add voting and alloc exclusions."""
        node = self.api_or_state_node
        if voting and (node.is_cm_eligible() or node.is_voting_only()):
            if not self._add_voting(scope, node):
                logger.error("Failed to add voting exclusion: %s.", node.name)
                if raise_error:
                    raise OpenSearchExclusionsException("Failed to add voting exclusion.")

        if allocation and node.is_data():
            try:
                success = self.opensearch_client.add_allocation_exclusions(
                    allocations={node.name}, alt_hosts=self.alt_hosts
                )
            except OpenSearchHttpError as e:
                logger.error(
                    "Failed to add shard allocation exclusion: %s. Error: %s",
                    node.name,
                    e,
                )
                success = False
            finally:
                if not success:
                    logger.error("Failed to add shard allocation exclusion: %s.", node.name)
                    if raise_error:
                        raise OpenSearchExclusionsException("Failed to add allocation exclusion.")

    def delete_current(
        self,
        scope: Scope,
        voting: bool = True,
        allocation: bool = True,
        raise_error: bool = False,
    ) -> None:
        """Delete voting and alloc exclusions."""
        name = self.state.unit_name
        if voting and not self._delete_voting({name}, scope):
            logger.error("Failed to delete voting exclusion: %s.", name)
            if raise_error:
                raise OpenSearchExclusionsException("Failed to delete voting exclusion.")

        if allocation and not self._delete_allocations({name}):
            logger.error("Failed to delete shard allocation exclusion: %s.", name)
            state = self.state.application if scope == Scope.APP else self.state.server
            state.allocation_exclusions_to_delete = state.allocation_exclusions_to_delete | {name}

            if raise_error:
                raise OpenSearchExclusionsException("Failed to delete allocation exclusion.")

    def cleanup(self, scope: Scope, nodes: list[Node]) -> None:
        """Delete all exclusions that failed to be deleted."""
        state = self.state.application if scope == Scope.APP else self.state.server

        node_names = {node.name for node in nodes}
        voting_exclusions_to_cleanup = self._units_to_cleanup(
            state.voting_exclusions_to_delete, node_names
        )
        allocations_to_cleanup = self._units_to_cleanup(
            state.allocation_exclusions_to_delete, node_names
        )
        if self.state.server.started and self.state.unit_name in node_names:
            # remove any leftover exclusions of this unit
            if self.state.unit_name in state.voting_exclusions_to_delete:
                voting_exclusions_to_cleanup.add(self.state.unit_name)
            if self.state.unit_name in state.allocation_exclusions_to_delete:
                allocations_to_cleanup.add(self.state.unit_name)

        if voting_exclusions_to_cleanup:
            self._delete_voting(voting_exclusions_to_cleanup, scope)
        if allocations_to_cleanup and self._delete_allocations(allocations_to_cleanup):
            state.allocation_exclusions_to_delete = (
                state.allocation_exclusions_to_delete - allocations_to_cleanup
            )

    def add_to_cleanup_list(self, unit_name: str, scope: Scope) -> None:
        """Add Voting and alloc exclusions for a target unit.

        This method is just a clean-up-later routine. We (re)add the unit to the exclusions and,
        hence, the leader of this app will be aware of this unit's removal and log it into its
        app-level peer data.
        """
        state = self.state.application if scope == Scope.APP else self.state.server
        state.allocation_exclusions_to_delete = state.allocation_exclusions_to_delete.union(
            {unit_name}
        )
        state.voting_exclusions_to_delete = state.voting_exclusions_to_delete.union({unit_name})

    def _units_to_cleanup(self, removable: set[str], node_names: set[str]) -> set[str]:
        """Returns all units that have left the cluster via Juju.

        This method ensures we keep a small list of voting exclusions at all times.

        Args:
            removable: the set of unit names that are marked as removable.
            node_names: the names of the nodes currently in the cluster.

        Returns:
            A set of unit names that should be removed from the voting exclusion list.
        """
        if (
            not (deployment_desc := self.state.application.deployment_desc)
            or not removable
            or not node_names
        ):
            return set()

        units = {format_unit_name(u, deployment_desc.app) for u in self.state.all_units}

        # Now, we need to remove the units that were marked for deletion and are not in the
        # cluster anymore.
        return removable - units - node_names

    def _add_voting(self, scope: Scope, node: Node, exclusions: set[str] | None = None) -> bool:
        """Include the current node in the CMs voting exclusions list of nodes.

        Args:
            scope: the scope of the exclusions to add (app or unit).
            node: the node for which the voting exclusion should be added.
            exclusions: the set of unit names to add to the voting exclusion list. If None, it
            defaults to the current node name.

        Returns:
            True if the operation succeeded, False otherwise.
        """
        try:
            to_add = exclusions or {node.name}
            result = self.opensearch_client.add_voting_exclusions(
                exclusions=to_add,
                alt_hosts=self.alt_hosts,
            )
            if scope == Scope.APP:
                self.state.application.voting_exclusions_to_delete = to_add.union(
                    self.state.application.voting_exclusions_to_delete
                )
            else:
                self.state.server.voting_exclusions_to_delete = to_add.union(
                    self.state.server.voting_exclusions_to_delete
                )

            # The voting excl. API returns a status only
            return result
        except OpenSearchHttpError:
            return False

    def _fetch_voting(self) -> set[str] | None:
        """Fetch the registered voting exclusions.

        Returns:
            A set of unit names that are currently in the voting exclusion list
            or None if the list could not be fetched.
        """
        try:
            return self.opensearch_client.fetch_voting_exclusions_config(alt_hosts=self.alt_hosts)
        except OpenSearchHttpError as e:
            logger.warning("Failed to fetch voting exclusions: %s", e)
            # unknown voting exclusion set
            return None

    def _delete_voting(self, exclusions: set[str], scope: Scope) -> bool:
        """Remove all voting exclusions and then re-adds the subset that should stay.

        The API does not allow to remove a subset of the voting exclusions, at once.

        Args:
            exclusions: the set of unit names to remove from the voting exclusion list.
            scope: the scope of the exclusions to delete (app or unit).

        Returns:
            True if the operation succeeded, False otherwise.
        """
        current_excl = self._fetch_voting()
        logger.debug("Current voting exclusions: %s", current_excl)
        if current_excl is None:
            return False

        if not current_excl & exclusions:
            logger.debug("No voting exclusions to delete, current set is %s", current_excl)
            self._remove_from_voting_cleanup(exclusions, scope)
            return True

        to_stay = current_excl - exclusions

        try:
            if not self.opensearch_client.remove_voting_exclusions(
                alt_hosts=self.alt_hosts,
            ):
                return False

            if to_stay:
                # Now, we register the units that should stay
                if not self.opensearch_client.add_voting_exclusions(
                    exclusions=to_stay,
                    alt_hosts=self.alt_hosts,
                ):
                    return False

            # Finally, we clean up the VOTING_TO_DELETE
            self._remove_from_voting_cleanup(exclusions, scope)
            return True
        except OpenSearchHttpError as e:
            logger.error("Failed to delete voting exclusions %s: %s", exclusions, e)
            return False

    def _remove_from_voting_cleanup(self, units: set[str], scope: Scope) -> None:
        """Remove the given unit names from the voting exclusions cleanup list."""
        state = self.state.application if scope == Scope.APP else self.state.server
        if pending := state.voting_exclusions_to_delete & units:
            state.voting_exclusions_to_delete = state.voting_exclusions_to_delete - pending

    def _delete_allocations(self, names: set[str]) -> bool:
        """This removes the allocation exclusions if needed.

        Args:
            names: the unit names to remove from the allocation exclusions.

        Returns:
            True if the operation succeeded, False otherwise.
        """
        try:
            existing = self.opensearch_client.fetch_allocation_exclusions(alt_hosts=self.alt_hosts)
            res = self.opensearch_client.add_allocation_exclusions(
                allocations=existing - names,
                override=True,
                alt_hosts=self.alt_hosts,
            )
            return res
        except OpenSearchHttpError:
            return False

    @cached_property
    def api_or_state_node(self) -> Node:
        """Return the current node configuration from API or state."""
        unit_id = self.state.server.unit_id
        node = None
        try:
            node = self.opensearch_client.get_current_node(
                self.state.unit_name, unit_id, self.alt_hosts, self.state.substrate
            )
            if not node:
                node = self.state.node_config
        except OpenSearchHttpError:
            node = self.state.node_config

        if node is None:
            raise OpenSearchExclusionsException(
                "Failed to acquire current node configuration both from API and state"
            )

        return node
