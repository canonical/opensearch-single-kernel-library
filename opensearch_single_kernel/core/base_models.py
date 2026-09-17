#!/usr/bin/env python3
# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Base model classes shared across all core models.

Includes:
    - PlainModel: base class for plain (non relation-backed) value objects.
    - Common cluster-wide value objects (App, Node, DeploymentDescription, ...).
"""

import re
from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import datetime
from enum import IntEnum
from hashlib import md5
from typing import Any, Literal

import poetry.core.constraints.version as poetry_version
from data_platform_helpers.advanced_statuses import StatusObject
from pydantic import (
    BaseModel,
    Field,
    field_serializer,
    field_validator,
    model_validator,
)
from typing_extensions import Self

from opensearch_single_kernel.common.constants import (
    _1GB_IN_KB,
    MAX_HEAP_SIZE_IN_KB,
    DeploymentType,
    Directive,
    PerformanceType,
    SmtpTransportSecurity,
    StartMode,
    State,
)
from opensearch_single_kernel.common.statuses import PeerClusterErrorDataStatuses
from opensearch_single_kernel.utils.enum import BaseStrEnum


def _sort_nested_dicts(obj: Any) -> Any:
    """Recursively sort dict keys so serialized output is deterministic."""
    if isinstance(obj, dict):
        return {k: _sort_nested_dicts(v) for k, v in sorted(obj.items())}
    if isinstance(obj, list):
        return [_sort_nested_dicts(item) for item in obj]
    return obj


def stripped_or_none(value: str | None) -> str | None:
    """Collapse empty or whitespace-only values to None."""
    return (value or "").strip() or None


class PlainModel(ABC, BaseModel):
    """Base model class."""

    def to_dict(self, by_alias: bool = False) -> dict[str, Any]:
        """Deserialize object into a dict."""
        return self.model_dump(by_alias=by_alias)

    @classmethod
    def from_dict(cls, input_dict: dict[str, Any] | None):
        """Create a new instance of this class from a json/dict repr."""
        if not input_dict:  # to handle when classes defined defaults
            return cls()
        return cls.model_validate(input_dict)

    def __eq__(self, other) -> bool:
        """Compare field-by-field, treating list fields as unordered."""
        if other is None:
            return False

        equal = True
        for attr_key, attr_val in self.__dict__.items():
            other_attr_val = getattr(other, attr_key)
            if isinstance(attr_val, list):
                equal = equal and sorted(attr_val) == sorted(other_attr_val)
            else:
                equal = equal and (attr_val == other_attr_val)

        return equal


class App(PlainModel):
    """Pydantic model representing an application."""

    id: str | None = None
    short_id: str | None = None
    name: str | None = None
    model_uuid: str | None = None

    @model_validator(mode="after")
    def set_props(self) -> Self:
        """Generate the attributes depending on the input."""
        # If all values are already set, we return self
        if all(v is not None for v in [self.id, self.name, self.model_uuid, self.short_id]):
            return self

        if not self.id and (self.name is None or self.model_uuid is None):
            raise ValueError("'id' or 'name and model_uuid' must be set.")

        if self.id:
            full_id_split = self.id.split("/")
            self.name = full_id_split[-1]
            self.model_uuid = full_id_split[0]
            app_id = self.id
        else:
            app_id = self.id = f"{self.model_uuid}/{self.name}"
        self.short_id = md5(app_id.encode()).hexdigest()[:3]

        return self


class Node(PlainModel):
    """Data class representing a node in a cluster."""

    name: str
    roles: list[str]
    ip: str
    app: App
    unit_number: int
    temperature: str | None = None

    @field_validator("roles")
    @classmethod
    def roles_set(cls, v):
        """Returns deduplicated sorted list of roles."""
        return sorted(set(v))

    def is_cm_eligible(self):
        """Returns whether this node is a cluster manager eligible member."""
        return "cluster_manager" in self.roles

    def is_voting_only(self):
        """Returns whether this node is a voting member."""
        return "voting_only" in self.roles

    def is_data(self):
        """Returns whether this node is a data* node."""
        for role in self.roles:
            if role.startswith("data"):
                return True

        return False


class DeploymentState(PlainModel):
    """Full state of a deployment, along with the juju status."""

    value: State
    message: str = Field(default="")

    @model_validator(mode="after")
    def prevent_none(self):
        """Validate the message or lack of depending on the state."""
        if self.value == State.ACTIVE:
            self.message = ""
        elif not self.message.strip():
            raise ValueError("The message must be set when state not Active.")

        return self


class PeerClusterConfig(PlainModel):
    """Model class for the multi-clusters related config set by the user."""

    cluster_name: str
    init_hold: bool
    roles: list[str]
    # Derived from a "data.<temperature>" role by the validator below; None when no
    # data-temperature role is configured
    data_temperature: str | None = None

    @model_validator(mode="after")
    def set_node_temperature(self):
        """Set and validate the node temperature."""
        allowed_temps = ["hot", "warm", "cold", "frozen", "content"]

        input_temps = set()
        for role in self.roles:
            if not role.startswith("data."):
                continue

            temp = role.split(".")[1]
            if temp not in allowed_temps:
                raise ValueError(f"data.'{temp}' not allowed. Allowed values: {allowed_temps}")

            input_temps.add(temp)

        if len(input_temps) > 1:
            raise ValueError("More than 1 data temperature provided.")
        elif input_temps:
            temperature = input_temps.pop()
            self.data_temperature = temperature

            self.roles.append("data")
            self.roles.remove(f"data.{temperature}")
            self.roles = list(set(self.roles))
        return self


class DeploymentDescription(PlainModel):
    """Model class describing the current state of a deployment."""

    app: App
    config: PeerClusterConfig
    start: StartMode
    pending_directives: list[Directive]
    typ: DeploymentType
    state: DeploymentState = DeploymentState(value=State.ACTIVE)
    cluster_name_autogenerated: bool = False
    promotion_time: float | None = None

    @model_validator(mode="after")
    def set_promotion_time(self):
        """Set promotion time of a failover to a main CM."""
        if not self.promotion_time and self.typ == DeploymentType.MAIN_ORCHESTRATOR:
            self.promotion_time = datetime.now().timestamp()

        return self


class PluginConfigInfo(PlainModel):
    """Model class for representing data needed to add or remove plugin configuration"""

    relation_name: str | None = None
    secret_name: str | None = None
    cleanup: dict[str, list[str]] = Field(default_factory=dict)

    @field_serializer("cleanup")
    def _sort_cleanup(self, value: dict[str, list[str]]) -> dict[str, list[str]]:
        """Sort nested dicts so serialized databag output is stable and order-independent."""
        return _sort_nested_dicts(value)

    def add_cleanup_items(self, cleanup: dict[str, list[str]]) -> None:
        """Merge items into cleanup dictionary avoiding duplicates."""
        for key, items in cleanup.items():
            current = self.cleanup.setdefault(key, [])
            self.cleanup[key] = sorted(list(set(current) | set(items)))


class PeerClusterRelErrorData(PlainModel):
    """Error state model an orchestrator broadcasts over a peer-cluster relation."""

    should_sever_relation: bool
    should_wait: bool
    blocked_message: str

    def get_status(self) -> StatusObject | None:
        """Get the status matching this error's blocked_message."""
        return self.get_status_from_message(self.blocked_message)

    @staticmethod
    def get_status_from_message(message: str) -> StatusObject | None:
        """Find the known PeerClusterErrorDataStatuses entry matching `message`.

        Status templates contain "{...}" placeholders for dynamic parts; each template
        is turned into a regex (placeholders become non-greedy wildcards) and matched
        against the concrete message. The returned status carries the concrete message.
        """
        for status in PeerClusterErrorDataStatuses:
            status_value: StatusObject = status.value
            escaped_message = re.escape(status_value.message)
            # Replace the (escaped) "{...}" placeholder blocks with non-greedy wildcards.
            regex_pattern = "^" + re.sub(r"\\\{.*?\\}", r"(?s:.*?)", escaped_message) + "$"
            if re.match(regex_pattern, message):
                return status_value.model_copy(update={"message": message})
        return None


class PeerClusterOrchestrators(PlainModel):
    """Model class for the PClusters registered main/failover clusters."""

    _TYPES = Literal["main", "failover"]

    main_rel_id: int = -1
    main_app: App | None = None
    failover_rel_id: int = -1
    failover_app: App | None = None

    def delete(self, typ: _TYPES) -> None:
        """Delete an orchestrator from the current pair."""
        if typ == "main":
            self.main_rel_id = -1
            self.main_app = None
        else:
            self.failover_rel_id = -1
            self.failover_app = None

    def promote_failover(self) -> None:
        """Delete previous main orchestrator and promote failover if any."""
        self.main_app = self.failover_app
        self.main_rel_id = self.failover_rel_id
        self.delete("failover")

    def check_relation_conflict(self, trigger: str, relation_id: int) -> bool:
        """Return whether the relation conflicts with an already connected orchestrator."""
        data = self.to_dict()
        return data.get(f"{trigger}_app") is not None and data.get(
            f"{trigger}_rel_id", -1
        ) not in [-1, relation_id]


class PeerClusterApp(PlainModel):
    """Model class for representing an application part of a large deployment."""

    app: App
    planned_units: int
    units: list[str]
    roles: list[str]

    @field_validator("units", "roles")
    @classmethod
    def sort_list(cls, v):
        """Returns deduplicated sorted list."""
        return sorted(set(v))


class UpgradeVersions(PlainModel):
    """Model class for the charm and workload versions used for upgrades."""

    charm: str
    workload: str

    @property
    def charm_parsed(self) -> poetry_version.Version:
        """Parsed charm version with build version omitted."""
        return poetry_version.Version.parse(self.charm.split("+")[0])

    @property
    def workload_parsed(self) -> poetry_version.Version:
        """Parsed workload version."""
        return poetry_version.Version.parse(self.workload)


class UnitUpgradesState(BaseStrEnum):
    """Unit state of upgrade."""

    HEALTHY = "healthy"
    RESTARTING = "restarting"  # Kubernetes only
    UPGRADING = "upgrading"  # Machines only
    OUTDATED = "outdated"  # Machines only


class LifecycleUnitTearingDownAndAppActive(IntEnum):
    """Unit is tearing down and 1+ other units are NOT tearing down"""

    FALSE = 0
    TRUE = 1
    UNKNOWN = 2

    def __bool__(self) -> bool:
        """Return bool evaluation."""
        return self is self.TRUE


class ProfileMemoryRequirements(PlainModel):
    """Memory requirements for a profile"""

    memory_size: int | None = None
    jvm_heap_percentage: float | None = None


class ClusterTopologyRequirements(PlainModel):
    """Cluster Topology requirements for a profile"""

    cluster_managers: int = 1
    data: int = 1


class OpenSearchProfile(ABC):
    """Abstract class for an OpenSearch profile"""

    type: PerformanceType

    @property
    @abstractmethod
    def memory_requirements(self) -> ProfileMemoryRequirements:
        """Get the memory requirements for this profile"""
        pass

    @property
    @abstractmethod
    def cluster_topology_requirements(self) -> ClusterTopologyRequirements:
        """Get the cluster topology requirements for this profile."""
        pass

    def get_jvm_heap_size(self, mem_size: float) -> int:
        """Get the JVM heap size in KB based on the memory requirements."""
        if self.memory_requirements.jvm_heap_percentage:
            return min(
                int(self.memory_requirements.jvm_heap_percentage * mem_size),
                MAX_HEAP_SIZE_IN_KB,
            )
        return _1GB_IN_KB

    def __hash__(self):
        """Get the hash of the profile."""
        return hash(self.type)

    def __eq__(self, value: object) -> bool:
        """Check equality with another OpenSearchProfile."""
        return self.type == value.type if isinstance(value, OpenSearchProfile) else False


class ProductionProfile(OpenSearchProfile):
    """Production profile for opensearch.

    Ensures cluster meets production minimal requirements
    """

    type = PerformanceType.PRODUCTION

    @property
    def memory_requirements(self) -> ProfileMemoryRequirements:
        """Get the memory requirements for this profile."""
        return ProfileMemoryRequirements(
            memory_size=8 * _1GB_IN_KB,
            jvm_heap_percentage=0.5,
        )

    @property
    def cluster_topology_requirements(self) -> ClusterTopologyRequirements:
        """Get the cluster topology requirements for this profile."""
        return ClusterTopologyRequirements(
            cluster_managers=3,
            data=3,
        )


class TestingProfile(OpenSearchProfile):
    """Testing profile for opensearch.

    Ensures basic system requirements and 1 CM+ 1 Data roles.
    """

    type = PerformanceType.TESTING

    @property
    def memory_requirements(self) -> ProfileMemoryRequirements:
        """Get the memory requirements for this profile."""
        return ProfileMemoryRequirements(
            memory_size=None,
            jvm_heap_percentage=None,
        )

    @property
    def cluster_topology_requirements(self) -> ClusterTopologyRequirements:
        """Get the cluster topology requirements for this profile."""
        return ClusterTopologyRequirements(
            cluster_managers=1,
            data=1,
        )


@dataclass(frozen=True)
class SmtpConfig:
    """SMTP-related config derived from relation data.

    Attributes:
        sender_email: From-address for the SMTP sender (relation smtp_sender).
        smtp_account_id: OpenSearch config id for the SMTP account (e.g. smtp-88_smtp-account).
        label: Plugin/config label for this relation (e.g. plugin-notifications-88).
        group_id: OpenSearch config id for the recipient group (e.g. smtp-88_recipients).
        channel_id: OpenSearch config id for the email channel (e.g. smtp-88_email-channel).
        transport_security: SMTP transport security (none, start_tls, tls).
    """

    sender_email: str
    smtp_account_id: str
    label: str
    group_id: str
    channel_id: str
    transport_security: SmtpTransportSecurity
