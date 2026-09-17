#!/usr/bin/env python3
# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Relations wrappers used by state to access models"""

import logging
import os
import time
from typing import Any, Optional

import ops
from dpcharmlibs.interfaces import (
    OpsPeerRepositoryInterface,
    OpsPeerUnitRepositoryInterface,
    OpsRelationRepositoryInterface,
)

from opensearch_single_kernel.common.constants import PerformanceType
from opensearch_single_kernel.core.base_models import (
    OpenSearchProfile,
    ProductionProfile,
    TestingProfile,
    UnitUpgradesState,
)
from opensearch_single_kernel.core.relation_models import (
    JWTAuthConfiguration,
    LockAppStateModel,
    LockServerStateModel,
    OpenSearchAppPeerModel,
    OpenSearchServerPeerModel,
    UpgradeAppModel,
    UpgradeServerModel,
)

logger = logging.getLogger(__name__)


class RelationState:
    """Base wrapper for models"""

    def __init__(
        self,
        relation: ops.model.Relation | None,
        interface: OpsPeerUnitRepositoryInterface[OpenSearchServerPeerModel]
        | OpsPeerRepositoryInterface[OpenSearchAppPeerModel]
        | OpsPeerRepositoryInterface[UpgradeAppModel]
        | OpsPeerUnitRepositoryInterface[UpgradeServerModel]
        | OpsPeerRepositoryInterface[LockAppStateModel]
        | OpsPeerUnitRepositoryInterface[LockServerStateModel]
        | OpsRelationRepositoryInterface[JWTAuthConfiguration],
        component: ops.model.Unit | ops.model.Application | None,
    ) -> None:
        self.relation = relation
        self.interface = interface
        self.component = component
        self.model = (
            self.interface.build_model(self.relation.id, component=self.component)
            if relation is not None
            else self.interface.model()
        )

    def __getattr__(self, name: str) -> Any:
        """Delegate unknown (non-private) reads to the underlying model."""
        if name.startswith("_"):
            raise AttributeError(name)
        model = self.__dict__.get("model")
        if model is None:
            raise AttributeError(name)
        return getattr(model, name)

    def __delattr__(self, name: str) -> None:
        """Reset a model field to its default."""
        self.delete(name)

    def update(self, items: dict[str, Any]) -> None:
        """Apply the given field changes and update the whole model in a single write."""
        if not self.relation or self.model is None:
            logger.warning(
                "Fields %s were attempted to be written on the relation before it exists.",
                list(items.keys()),
            )
            return

        for field, value in items.items():
            setattr(self.model, field.replace("-", "_"), value)

        self.interface.write_model(self.relation.id, self.model)

    def delete(self, *fields: str) -> None:
        """Reset the given fields to their declared defaults (extras to None)."""
        if not self.relation or self.model is None:
            logger.warning(
                "Fields %s were attempted to be deleted on the relation before it exists.",
                list(fields),
            )
            return

        for field in fields:
            field_info = type(self.model).__pydantic_fields__.get(field)
            default = field_info.get_default(call_default_factory=True) if field_info else None
            setattr(self.model, field, default)

        self.interface.write_model(self.relation.id, self.model)


class LockApplication(RelationState):
    """State/relation-data wrapper for the Lock application databag."""

    model: LockAppStateModel

    def __init__(
        self,
        relation: ops.model.Relation | None,
        interface: OpsPeerRepositoryInterface[LockAppStateModel],
        component: ops.model.Application,
    ):
        super().__init__(relation, interface, component)
        self.unit = component

    def grant_lock(self, unit_name: str, own_unit_name: str) -> None:
        """Grant the peer lock to `unit_name`.

        If the lock is granted to the local (leader) unit, also record the Juju event
        during which it happened: see
        LockAppStateModel.leader_acquired_lock_after_juju_event_id for why. Prevent leader
        unit from using lock in the same Juju event that it was granted. If the charm code
        raises an uncaught exception later in the Juju event, `unit-with-lock` will be
        reverted to its previous value which could allow another unit to get the lock.
        Therefore, we cannot use the lock in this Juju event. We must wait until the next
        Juju event, when `unit-with-lock` has been committed (i.e. won't be reverted), to
        use the lock.
        """
        assert self.model.unit_with_lock != unit_name
        items: dict = {"unit_with_lock": unit_name}
        if unit_name == own_unit_name:
            items["leader_acquired_lock_after_juju_event_id"] = os.environ.get(
                "JUJU_CONTEXT_ID", None
            )
        self.update(items)

    def release_lock(self) -> None:
        """Release the lock and clear `leader_acquired_lock_after_juju_event_id`."""
        if not self.model.unit_with_lock:
            return
        self.delete("unit_with_lock", "leader_acquired_lock_after_juju_event_id")


class LockServer(RelationState):
    """State/relation-data wrapper for the Lock unit databag."""

    model: LockServerStateModel

    def __init__(
        self,
        relation: ops.model.Relation | None,
        interface: OpsPeerUnitRepositoryInterface[LockServerStateModel],
        component: ops.model.Unit,
    ):
        super().__init__(relation, interface, component)
        self.unit = component

    def trigger_relation_changed(self) -> None:
        """Trigger relation changed event on other units by writing to a dummy field."""
        self.update({"trigger": os.environ.get("JUJU_CONTEXT_ID", "")})


class OpenSearchApplication(RelationState):
    """State/relation-data wrapper for the OpenSearch application peer databag."""

    model: OpenSearchAppPeerModel

    def __init__(
        self,
        relation: ops.model.Relation | None,
        interface: OpsPeerRepositoryInterface[OpenSearchAppPeerModel],
        component: ops.model.Application,
    ):
        super().__init__(relation, interface, component)
        self.unit = component

    @property
    def name(self) -> str:
        """Return the name of the Application this wrapper is bound to."""
        return self.unit.name

    def initialize_empty_secrets(self) -> None:
        """Initialize empty app-level secrets to prevent log spam.

        The v1 lib only creates a Juju secret when the written value is truthy.
        We write a single-space placeholder to force creation and leave it in place
        callers strip the value before use so the placeholder is never
        mistaken for real data.
        """
        items: dict = {}
        if not self.model.plugin_secrets:
            items["plugin_secrets"] = "{}"
        if not self.model.admin_password:
            items["admin_password"] = " "
        if not self.model.admin_key_password:
            items["admin_key_password"] = " "
        if items:
            self.update(items)


class OpenSearchServer(RelationState):
    """State/relation-data wrapper for a single OpenSearch unit's peer databag."""

    model: OpenSearchServerPeerModel

    def __init__(
        self,
        relation: ops.model.Relation | None,
        interface: OpsPeerUnitRepositoryInterface[OpenSearchServerPeerModel],
        component: ops.model.Unit,
    ):
        super().__init__(relation, interface, component)
        self.unit = component

    @property
    def unit_id(self) -> int:
        """The id of the unit this wrapper is bound to, from its unit name."""
        return int(self.component.name.split("/")[1])

    @property
    def opensearch_profile(self) -> Optional[OpenSearchProfile]:
        """Current profile of the unit, as an OpenSearchProfile instance."""
        if not self.model.profile:
            return None
        return (
            ProductionProfile()
            if self.model.profile == PerformanceType.PRODUCTION
            else TestingProfile()
        )

    def initialize_empty_secrets(self) -> None:
        """Initialize empty unit-level secrets to prevent log spam."""
        # Use truthy placeholders only for fields whose secrets don't exist yet
        items: dict = {}
        if not self.model.transport_key_password:
            items["transport_key_password"] = " "
        if not self.model.http_key_password:
            items["http_key_password"] = " "
        if items:
            self.update(items)


class UpgradeApplication(RelationState):
    """State/relation-data wrapper for the upgrade application databag."""

    model: UpgradeAppModel

    def __init__(
        self,
        relation: ops.model.Relation | None,
        interface: OpsPeerRepositoryInterface[UpgradeAppModel],
        component: ops.model.Application,
    ):
        super().__init__(relation, interface, component)
        self.unit = component

    def set_upgrade_resumed(self, value: bool) -> None:
        """Set whether user has resumed upgrade with Juju action."""
        self.update({"upgrade_resume_last_updated": str(time.time()), "upgrade_resumed": value})


class UpgradeServer(RelationState):
    """State/relation-data wrapper for the upgrade unit databag."""

    model: UpgradeServerModel

    def __init__(
        self,
        relation: ops.model.Relation | None,
        interface: OpsPeerUnitRepositoryInterface[UpgradeServerModel],
        component: ops.model.Unit,
    ):
        super().__init__(relation, interface, component)

    @property
    def unit_number(self) -> int:
        """Get the unit number this wrapper is bound to."""
        return int(self.component.name.split("/")[-1])

    def set_unit_state(self, value: "UnitUpgradesState") -> None:
        """Set the unit upgrade state."""
        self.update({"state": value.value})
