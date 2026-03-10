#!/usr/bin/env python3

# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

"""Collection of models used for the operation of the charm."""

import json
import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import datetime
from hashlib import md5
from typing import Any, Iterator, Literal

from pydantic import BaseModel, Field, RootModel, field_validator, model_validator

from opensearch_single_kernel.common.constants import (
    _1GB_IN_KB,
    MAX_HEAP_SIZE_IN_KB,
    DeploymentType,
    Directive,
    PerformanceType,
    StartMode,
    State,
)
from opensearch_single_kernel.lib.charms.smtp_integrator.v0.smtp import (
    TransportSecurity,
)

logger = logging.getLogger(__name__)


class Model(ABC, BaseModel):
    """Base model class."""

    def __init__(self, **data: Any) -> None:
        super().__init__(**data)

    def to_str(self, by_alias: bool = False) -> str:
        """Deserialize object into a string."""
        return json.dumps(Model.sort_payload(self.to_dict(by_alias=by_alias)))

    def to_dict(self, by_alias: bool = False) -> dict[str, Any]:
        """Deserialize object into a dict."""
        return self.dict(by_alias=by_alias)

    @classmethod
    def from_dict(cls, input_dict: dict[str, Any] | None):
        """Create a new instance of this class from a json/dict repr."""
        if not input_dict:  # to handle when classes defined defaults
            return cls()
        return cls(**input_dict)

    @classmethod
    def from_str(cls, input_str_dict: str):
        """Create a new instance of this class from a stringified json/dict repr."""
        return cls.parse_raw(input_str_dict)

    @staticmethod
    def sort_payload(payload: Any) -> Any:
        """Sort input payloads to avoid rel-changed events for same unordered objects."""
        if isinstance(payload, dict):
            # Sort dictionary by keys
            return {key: Model.sort_payload(value) for key, value in sorted(payload.items())}
        elif isinstance(payload, list):
            # Sort each item in the list and then sort the list
            sorted_list = [Model.sort_payload(item) for item in payload]
            try:
                return sorted(sorted_list)
            except TypeError:
                # If items are not sortable, return as is
                return sorted_list
        else:
            # Return the value as is for non-dict, non-list types
            return payload

    def __eq__(self, other) -> bool:
        """Implement equality."""
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


class App(Model):
    """Data class representing an application."""

    id: str | None = None
    short_id: str | None = None
    name: str | None = None
    model_uuid: str | None = None

    @model_validator(mode="after")
    def set_props(self):
        """Generate the attributes depending on the input."""
        # If all values are not None, we return self
        if None not in [self.id, self.name, self.model_uuid, self.short_id]:
            return self

        if not self.id and None in [self.name, self.model_uuid]:
            raise ValueError("'id' or 'name and model_uuid' must be set.")

        if self.id:
            full_id_split = self.id.split("/")
            self.name, self.model_uuid = full_id_split[-1], full_id_split[0]
        else:
            self.id = f"{self.model_uuid}/{self.name}"
        self.short_id = md5(self.id.encode()).hexdigest()[:3]

        return self


class Node(Model):
    """Data class representing a node in a cluster."""

    name: str
    roles: list[str]
    ip: str
    app: App
    unit_number: int
    temperature: str | None = None

    @classmethod
    @field_validator("roles")
    def roles_set(cls, v):
        """Returns deduplicated list of roles."""
        return list(set(v))

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


class PeerClusterOrchestrators(Model):
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


class PeerClusterConfig(Model):
    """Model class for the multi-clusters related config set by the user."""

    cluster_name: str
    init_hold: bool
    roles: list[str]
    # We have a breaking change in the model
    # For older charms, this field will not exist and they will be set in the
    # profile called "testing".
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


class PeerClusterApp(Model):
    """Model class for representing an application part of a large deployment."""

    app: App
    planned_units: int
    units: list[str]
    roles: list[str]


class PeerClusterFleetApps(RootModel[dict[str, PeerClusterApp]]):
    """Model class for all applications in a large deployment as a dict."""

    def __iter__(self) -> Iterator[str]:
        """Implements the iter magic method."""
        return iter(self.root)

    def __getitem__(self, item: str) -> PeerClusterApp:
        """Implements the getitem magic method."""
        return self.root[item]


class DeploymentState(Model):
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


class DeploymentDescription(Model):
    """Model class describing the current state of a deployment / sub-cluster."""

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


class ProfileMemoryRequirements(Model):
    """Memory requirements for a profile"""

    memory_size: int | None = None
    jvm_heap_percentage: float | None = None


class ClusterTopologyRequirements(Model):
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


class PluginConfigInfo(Model):
    """Model class for representing data needed to add or remove plugin configuration"""

    relation_name: str | None = None
    secret_id: str | None = None
    cleanup: dict[str, list[str]] = Field(default_factory=dict)

    def add_cleanup_items(self, cleanup: dict[str, list[str]]) -> None:
        """Merge items into cleanup dictionary avoiding duplicates."""
        for key, items in cleanup.items():
            current = self.cleanup.setdefault(key, [])
            for item in items:
                if item not in current:
                    current.append(item)


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
    transport_security: TransportSecurity
