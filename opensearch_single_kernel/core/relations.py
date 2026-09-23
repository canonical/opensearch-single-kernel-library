#!/usr/bin/env python3
# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Relations wrappers used by state to access models"""

import json
import logging
import os
import time
from typing import Any, Optional

import ops
from dpcharmlibs.interfaces import OpsRepository, build_model, write_model
from pydantic import BaseModel

from opensearch_single_kernel.common.constants import PerformanceType
from opensearch_single_kernel.core.base_models import (
    OpenSearchProfile,
    ProductionProfile,
    TestingProfile,
    UnitUpgradesState,
)
from opensearch_single_kernel.core.relation_models import (
    LockAppStateModel,
    LockServerStateModel,
    OpenSearchAppPeerModel,
    OpenSearchServerPeerModel,
    PeerClusterAppModel,
    PeerClusterServerModel,
    UpgradeAppModel,
    UpgradeServerModel,
)

logger = logging.getLogger(__name__)


class RelationState:
    """Base wrapper for models"""

    # Wrapper-internal attributes that must never be routed to the databag. Used to avoid setattr on this fields
    RESERVED_ATTRS = {"repository", "component", "relation", "skip_secrets", "model", "unit"}

    def __init__(
        self,
        model_cls: type[BaseModel],
        repository: OpsRepository | None,
        component: ops.model.Unit | ops.model.Application | None = None,
        skip_secrets: bool = False,
    ) -> None:
        self.repository = repository
        self.component = (
            component if component is not None else getattr(repository, "component", None)
        )
        self.relation = self.repository.relation if self.repository is not None else None
        self.skip_secrets = skip_secrets
        self.model = build_model(repository, model_cls) if repository else model_cls()

    def __getattr__(self, name: str) -> Any:
        """Delegate unknown reads to the underlying model."""
        model = self.__dict__.get("model")
        if model is None:
            raise AttributeError(name)
        return getattr(model, name)

    def __setattr__(self, name: str, value: Any) -> None:
        """Update model-field writes to the databag."""
        model = self.__dict__.get("model")
        if (
            name not in self.RESERVED_ATTRS
            and model is not None
            and name in type(model).model_fields
        ):
            self.update({name: value})
        else:
            object.__setattr__(self, name, value)

    def __delattr__(self, name: str) -> None:
        """Reset a single model field to its default and write."""
        self.reset(name)

    def reset(self, *names: str) -> None:
        """Reset the given model field(s) to their default(s) in a single write."""
        if not self.repository or self.model is None:
            logger.warning(
                "Fields %s were attempted to be deleted on the relation before it exists.",
                list(names),
            )
            return

        for field in names:
            field_info = type(self.model).model_fields.get(field)
            default = field_info.get_default(call_default_factory=True) if field_info else None
            setattr(self.model, field, default)

        self.write()

    def update(self, items: dict[str, Any]) -> None:
        """Apply the given field changes and update the whole model in a single write."""
        if not self.repository or self.model is None:
            logger.warning(
                "Fields %s were attempted to be written on the relation before it exists.",
                list(items.keys()),
            )
            return

        for field, value in items.items():
            setattr(self.model, field.replace("-", "_"), value)

        self.write()

    def write(self) -> None:
        """Write the whole model."""
        write_model(
            self.repository,
            self.model,
            context={"skip_secrets": "true"} if self.skip_secrets else None,
        )

        # TODO: remove then https://github.com/canonical/data-platform-libs/issues/272 is fixed
        dumped = self.model.model_dump(
            mode="json", context={"skip_secrets": "true"}, exclude_none=True
        )
        for field, value in dumped.items():
            serialized = value if isinstance(value, str) else json.dumps(value)
            if not serialized:
                self.repository.delete_field(field)


class LockApplication(RelationState):
    """State wrapper for the Lock application databag."""

    model: LockAppStateModel

    def __init__(
        self,
        repository: OpsRepository | None,
        component: ops.model.Application,
    ):
        super().__init__(LockAppStateModel, repository, component)
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
        self.reset("unit_with_lock", "leader_acquired_lock_after_juju_event_id")


class LockServer(RelationState):
    """State wrapper for the Lock unit databag."""

    model: LockServerStateModel

    def __init__(
        self,
        repository: OpsRepository | None,
        component: ops.model.Unit,
    ):
        super().__init__(LockServerStateModel, repository, component)
        self.unit = component

    def trigger_relation_changed(self) -> None:
        """Trigger relation changed event on other units by writing to a dummy field."""
        self.trigger = os.environ.get("JUJU_CONTEXT_ID", "")


class OpenSearchApplication(RelationState):
    """State wrapper for the OpenSearch application databag."""

    model: OpenSearchAppPeerModel

    def __init__(
        self,
        repository: OpsRepository | None,
        component: ops.model.Application,
    ):
        super().__init__(OpenSearchAppPeerModel, repository, component)
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
    """State wrapper for the OpenSearch unit databag."""

    model: OpenSearchServerPeerModel

    def __init__(
        self,
        repository: OpsRepository | None,
        component: ops.model.Unit,
    ):
        super().__init__(OpenSearchServerPeerModel, repository, component)
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
        items: dict = {}
        if not self.model.transport_key_password:
            items["transport_key_password"] = " "
        if not self.model.http_key_password:
            items["http_key_password"] = " "
        if items:
            self.update(items)


class UpgradeApplication(RelationState):
    """State wrapper for the Upgrades application databag."""

    model: UpgradeAppModel

    def __init__(
        self,
        repository: OpsRepository | None,
        component: ops.model.Application,
    ):
        super().__init__(UpgradeAppModel, repository, component)
        self.unit = component

    def set_upgrade_resumed(self, value: bool) -> None:
        """Set whether user has resumed upgrade with Juju action."""
        self.update({"upgrade_resume_last_updated": str(time.time()), "upgrade_resumed": value})


class UpgradeServer(RelationState):
    """State wrapper for the Upgrades unit databag."""

    model: UpgradeServerModel

    def __init__(
        self,
        repository: OpsRepository | None,
        component: ops.model.Unit,
    ):
        super().__init__(UpgradeServerModel, repository, component)

    @property
    def unit_number(self) -> int:
        """Get the unit number this wrapper is bound to."""
        return int(self.component.name.split("/")[-1])

    def set_unit_state(self, value: "UnitUpgradesState") -> None:
        """Set the unit upgrade state."""
        self.state = value.value


class PeerClusterApplication(RelationState):
    """State wrapper for the peer cluster application databag."""

    model: PeerClusterAppModel

    def __init__(
        self,
        repository: OpsRepository | None,
        component: ops.model.Application | None = None,
        skip_secrets: bool = False,
    ) -> None:
        super().__init__(PeerClusterAppModel, repository, component, skip_secrets)

    def empty_secret_placeholders(self) -> dict[str, Any]:
        """Return the placeholder field changes that pre-create the secret groups."""
        if self.model.pc_secrets_initialized:
            return {}
        return {
            "admin_password": self.model.admin_password or " ",
            "admin_cert": self.model.admin_cert or " ",
            "plugin_secrets": self.model.plugin_secrets or " ",
            "pc_secrets_initialized": True,
        }


class PeerClusterServer(RelationState):
    """State wrapper for the peer cluster unit databag."""

    model: PeerClusterServerModel

    def __init__(
        self,
        repository: OpsRepository | None,
        component: ops.model.Unit | None = None,
        skip_secrets: bool = False,
    ) -> None:
        super().__init__(PeerClusterServerModel, repository, component, skip_secrets)

    @property
    def unit(self) -> ops.model.Unit:
        """The ops.Unit this wrapper's data is bound to."""
        return self.component
