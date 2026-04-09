#!/usr/bin/env python3

# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Collection of models used for the operation of the charm."""

import base64
import binascii
import json
import logging
import re
from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import datetime
from enum import IntEnum
from hashlib import md5
from typing import Any, Callable, Iterator, Literal, Optional

import poetry.core.constraints.version as poetry_version
from data_platform_helpers.advanced_statuses import StatusObject
from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    RootModel,
    field_serializer,
    field_validator,
    model_serializer,
    model_validator,
)
from typing_extensions import Annotated, Self

from opensearch_single_kernel.common.constants import (
    _1GB_IN_KB,
    MAX_HEAP_SIZE_IN_KB,
    SECRET_APP_ADMIN,
    SECRET_BACKUPS,
    SECRET_PLUGIN,
    SECRET_UNIT_HTTP,
    SECRET_UNIT_TRANSPORT,
    SECRET_USERS,
    DeploymentType,
    Directive,
    PerformanceType,
    SmtpTransportSecurity,
    StartMode,
    State,
)
from opensearch_single_kernel.common.statuses import PeerClusterErrorDataStatuses
from opensearch_single_kernel.lib.charms.data_platform_libs.v1.data_interfaces import (
    BaseCommonModel,
    ExtraSecretStr,
    OptionalSecretStr,
    PeerModel,
    ResourceProviderModel,
)
from opensearch_single_kernel.utils.enum import BaseStrEnum

logger = logging.getLogger(__name__)


BackupSecretKeyStr = Annotated[
    OptionalSecretStr, Field(exclude=True, default=None), SECRET_BACKUPS
]
TransportSecretStr = Annotated[
    OptionalSecretStr, Field(exclude=True, default=None), SECRET_UNIT_TRANSPORT
]
HttpSecretStr = Annotated[OptionalSecretStr, Field(exclude=True, default=None), SECRET_UNIT_HTTP]
AdminSecretStr = Annotated[OptionalSecretStr, Field(exclude=True, default=None), SECRET_APP_ADMIN]
UserSecretStr = Annotated[OptionalSecretStr, Field(exclude=True, default=None), SECRET_USERS]
PluginsSecretStr = Annotated[OptionalSecretStr, Field(exclude=True, default=None), SECRET_PLUGIN]


def _sort_nested_dicts(obj: Any) -> Any:
    """Recursively sort dict keys so serialized output is deterministic."""
    if isinstance(obj, dict):
        return {k: _sort_nested_dicts(v) for k, v in sorted(obj.items())}
    if isinstance(obj, list):
        return [_sort_nested_dicts(item) for item in obj]
    return obj


class Model(ABC, BaseModel):
    """Base model class."""

    def __init__(self, **data: Any) -> None:
        super().__init__(**data)

    def to_str(self, by_alias: bool = False) -> str:
        """Deserialize object into a string."""
        return json.dumps(Model.sort_payload(self.to_dict(by_alias=by_alias)))

    def to_dict(self, by_alias: bool = False) -> dict[str, Any]:
        """Deserialize object into a dict."""
        return self.model_dump(by_alias=by_alias)

    @classmethod
    def from_dict(cls, input_dict: dict[str, Any] | None):
        """Create a new instance of this class from a json/dict repr."""
        if not input_dict:  # to handle when classes defined defaults
            return cls()
        return cls(**input_dict)

    @classmethod
    def from_str(cls, input_str_dict: str):
        """Create a new instance of this class from a stringified json/dict repr."""
        return cls.model_validate_json(input_str_dict)

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


class PeerClusterConfig(Model):
    """Model class for the multi-clusters related config set by the user."""

    cluster_name: str
    init_hold: bool
    roles: list[str]
    # We have a breaking change in the model
    # For older charms, this field will not exist, and they will be set in the
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
    secret_name: str | None = None
    cleanup: dict[str, list[str]] = Field(default_factory=dict)

    @field_serializer("cleanup")
    def _sort_cleanup(self, value: dict[str, list[str]]) -> dict[str, list[str]]:
        return _sort_nested_dicts(value)

    def add_cleanup_items(self, cleanup: dict[str, list[str]]) -> None:
        """Merge items into cleanup dictionary avoiding duplicates."""
        for key, items in cleanup.items():
            current = self.cleanup.setdefault(key, [])
            self.cleanup[key] = sorted(list(set(current) | set(items)))


# --- Backup related models ---
class _StorageRelDataMixin:
    """Mixin providing from_relation for storage relation data models."""

    @classmethod
    def from_relation(cls, data: dict[str, str]) -> "Self":
        normalized = {k.replace("-", "_"): v for k, v in data.items()}
        return cls.model_validate(normalized)


class GcsRelData(_StorageRelDataMixin, BaseModel):
    """Pydantic model for GCS relation data."""

    model_config = ConfigDict(populate_by_name=True, extra="ignore")
    secret_key: BackupSecretKeyStr = Field(default=None)
    path: str | None = Field(default=None)
    bucket: str | None = Field(default=None)
    endpoint: str | None = Field(default=None)
    storage_class: str | None = Field(alias="storage-class", default=None)

    @model_validator(mode="after")
    def validate_core_fields(self):
        """Validate the core fields of the gcs relation data."""
        if not self.secret_key:
            raise ValueError("Missing fields: secret-key")

        content = self.secret_key.strip()
        if content.startswith("{") and content.endswith("}"):
            try:
                json.loads(content)
            except (ValueError, TypeError):
                raise ValueError("secret-key is not valid JSON (may be an unresolved secret URI)")
        else:
            # gcs-integrator may base64-encode the service account JSON
            try:
                decoded = (
                    base64.b64decode(content, altchars=b"-_", validate=True)
                    .decode("utf-8")
                    .strip()
                )
                json.loads(decoded)
                self.secret_key = decoded
            except (binascii.Error, ValueError, UnicodeDecodeError):
                raise ValueError("secret-key is not valid JSON (may be an unresolved secret URI)")

        if not self.bucket:
            raise ValueError("Missing field: bucket")

        # remove any duplicate, prefix or trailing "/" characters
        if path := self.path:
            path = re.sub(r"/+", "/", path).strip().strip("/")
        self.path = path or None

        return self


class AzureRelData(_StorageRelDataMixin, BaseModel):
    """Pydantic model for Azure relation data."""

    model_config = ConfigDict(populate_by_name=True, extra="ignore")

    storage_account: BackupSecretKeyStr = Field(default=None)
    secret_key: BackupSecretKeyStr = Field(default=None)

    container: str | None = Field(default=None)
    endpoint: str | None = Field(default=None)
    path: str | None = Field(default=None)
    connection_protocol: str | None = Field(alias="connection-protocol", default=None)

    @model_validator(mode="after")
    def validate_core_fields(self):  # noqa: N805
        """Validate the core fields of the azure relation data."""
        if not self.storage_account or not self.secret_key:
            raise ValueError("Missing fields: storage_account, secret_key")

        # remove any duplicate, prefix or trailing "/" characters
        if path := self.path:
            path = re.sub(r"/+", "/", path).strip().strip("/")
        self.path = path or None

        return self


class S3RelData(_StorageRelDataMixin, BaseModel):
    """Pydantic model for S3 relation data."""

    model_config = ConfigDict(populate_by_name=True, extra="ignore")

    access_key: BackupSecretKeyStr = Field(default=None)
    secret_key: BackupSecretKeyStr = Field(default=None)
    tls_ca_chain: BackupSecretKeyStr = Field(default=None)

    bucket: str | None = Field(default=None)
    region: str | None = Field(default=None)
    endpoint: str | None = Field(default=None)
    path: str | None = Field(default=None)
    protocol: str | None = Field(default=None)
    s3_uri_style: str | None = Field(default=None)
    storage_class: str | None = Field(default=None)

    @model_validator(mode="after")
    def validate_core_fields(self):
        """Validate the core fields of the S3 relation data."""
        if not self.access_key or not self.secret_key:
            raise ValueError("Missing fields: access_key, secret_key")

        # NOTE: Both bucket and endpoint must be set. If none of them are set,
        # but credentials were found, this likely means that we are validating for a
        # non cluster_manager application, which only needs credentials.
        if self.bucket and not self.endpoint:
            raise ValueError("Missing field: endpoint")
        if self.endpoint and not self.bucket:
            raise ValueError("Missing field: bucket")
        if not self.region:
            raise ValueError("Missing field: region")
        if not self.access_key:
            raise ValueError("Missing field: access_key")
        if not self.secret_key:
            raise ValueError("Missing field: secret_key")

        # remove any duplicate, prefix or trailing "/" characters
        if path := self.path:
            path = re.sub(r"/+", "/", path).strip().strip("/")
        self.path = path or None

        return self

    @field_validator("tls_ca_chain", mode="before", check_fields=False)
    @classmethod
    def _tls_chain(cls, v):  # noqa: N805
        if v is None:
            return None
        if isinstance(v, (bytes, bytearray)):
            v = v.decode()
        if isinstance(v, list):
            return "\n".join(s.strip() for s in v if s)
        if isinstance(v, dict):
            chain = v.get("chain")
            if isinstance(chain, list):
                return "\n".join(s.strip() for s in chain if s)

            return json.dumps(v)
        return str(v)

    @field_validator("s3_uri_style", mode="before")
    @classmethod
    def change_path_style_type(cls, value) -> bool:
        """Coerce a type change of the s3_uri_style into a bool."""
        if isinstance(value, str):
            return value.lower() == "path"
        return bool(value)

    @staticmethod
    def get_endpoint_protocol(endpoint: str) -> str:
        """Returns the protocol based on the endpoint."""
        if not endpoint:
            return "https"

        if endpoint.startswith("http://"):
            return "http"
        return "https"


class ObjectStorageConfig(Model):
    """Model class for the object storage config - for all clouds."""

    s3: S3RelData | None = None
    azure: AzureRelData | None = None
    gcs: GcsRelData | None = None


class PeerClusterRelErrorData(Model):
    """Model class for the PCluster relation data."""

    cluster_name: str | None
    should_sever_relation: bool
    should_wait: bool
    blocked_message: str
    deployment_desc: DeploymentDescription | None

    def get_status(self) -> StatusObject | None:
        """Get the status of the error data."""
        # We need to find the status based on the blocked_message
        # and the should_wait which means its a waiting status
        for status in PeerClusterErrorDataStatuses:
            escaped_message = re.escape(status.value.message)

            # Substitute the escaped curly brace blocks with non-greedy wildcard
            # Note the triple backslashes: \\\{ matches the literal string "\{"
            regex_pattern = "^" + re.sub(r"\\\{.*?\\\}", r"(?s:.*?)", escaped_message) + "$"

            if re.match(regex_pattern, self.blocked_message):
                # set message to the original message with placeholders
                new_status = status.value.model_copy(update={"message": self.blocked_message})
                return new_status
        return None

    @staticmethod
    def get_status_from_message(message: str) -> StatusObject | None:
        """Get the status of the error data based on the message."""
        for status in PeerClusterErrorDataStatuses:
            escaped_message = re.escape(status.value.message)
            regex_pattern = "^" + re.sub(r"\\\{.*?\\\}", r"(?s:.*?)", escaped_message) + "$"
            if re.match(regex_pattern, message):
                new_status = status.value.model_copy(update={"message": message})
                return new_status
        return None


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

    def check_relation_conflict(self, trigger: str, relation_id: int) -> bool:
        """Return whether the relation conflicts with an already connected orchestrator."""
        data = self.to_dict()
        return data.get(f"{trigger}_app") is not None and data.get(
            f"{trigger}_rel_id", -1
        ) not in [-1, relation_id]


class PeerClusterApp(Model):
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


class PeerClusterFleetApps(RootModel[dict[str, PeerClusterApp]]):
    """Model class for all applications in a large deployment as a dict."""

    def __iter__(self) -> Iterator[str]:
        """Implements the iter magic method."""
        return iter(self.root)

    def __getitem__(self, item: str) -> PeerClusterApp:
        """Implements the getitem magic method."""
        return self.root[item]


class PeerClusterServerModel(PeerModel):
    """Pydantic model for peer cluster unit-level databag."""

    tls_ca_renewing: bool = Field(default=False)
    tls_ca_renewed: bool = Field(default=False)
    tls_configured: bool = Field(default=False)
    snapshots_credentials_saved: str = Field(default="")


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


class LockAppStateModel(PeerModel):
    """Peer model mapping to the Lock application state."""

    leader_acquired_lock_after_juju_event_id: str | None = Field(default=None)
    unit_with_lock: str | None = Field(default=None)
    lock_granted_after_juju_event_id: str | None = Field(default=None)


class LockServerStateModel(PeerModel):
    """Peer model mapping to the Lock unit state."""

    lock_requested: bool = Field(default=False)
    lock_acquired_after_juju_event_id: str | None = Field(default=None)


class JWTAuthConfiguration(ResourceProviderModel):
    """Model class for the configuration parameters of JWT authentication."""

    signing_key: ExtraSecretStr = Field(default=None)
    jwt_header: str | None = Field(default=None)
    jwt_url_parameter: str | None = Field(default=None)
    roles_key: str | None = Field(default=None)
    subject_key: str | None = Field(default=None)
    required_audience: str | None = Field(default=None)
    required_issuer: str | None = Field(default=None)
    jwt_clock_skew_tolerance_seconds: int | None = Field(default=None)


class ModelProperty:
    """Descriptor to proxy attributes directly to the underlying Pydantic model."""

    def __init__(self, name: str, default: Any = None, default_factory: Callable = None):
        self.name = name
        self.default = default
        self.default_factory = default_factory

    def __get__(self, obj, objtype=None):
        """Getter for properties"""
        if obj is None:
            return self

        model = obj.model
        if model:
            val = getattr(model, self.name, None)
            if val is not None:
                return val

        if self.default_factory:
            return self.default_factory()
        return self.default

    def __set__(self, obj, value):
        """Setter for properties"""
        model = obj.model
        if model:
            setattr(model, self.name, value)
            obj.write(model)
        else:
            logger.warning(
                f"Attempted to set '{self.name}' to '{value}', "
                "but the relation model is missing."
            )

    def __delete__(self, obj):
        """Reset the field to its default value."""
        default = self.default_factory() if self.default_factory else self.default
        self.__set__(obj, default)


class UpgradeVersions(Model):
    """Model class for the charm & workload versions used for upgrades."""

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


class UpgradeAppModel(PeerModel):
    """Pydantic model for the upgrade application-level databag."""

    versions: Optional[UpgradeVersions] = Field(default=None)
    upgrade_resumed: bool = Field(default=False)
    upgrade_resume_last_updated: Optional[str] = Field(
        default=None, alias="-unused-timestamp-upgrade-resume-last-updated"
    )

    @field_validator("upgrade_resume_last_updated", mode="before")
    @classmethod
    def coerce_to_str(cls, v):
        """Coerce numeric timestamp stored as float in legacy databags to str."""
        if v is None:
            return None
        return str(v)


class UpgradeServerModel(PeerModel):
    """Pydantic model for the upgrade unit-level databag."""

    state: Optional[str] = Field(default=None)
    snap_revision: Optional[str] = Field(default=None)
    workload_version: Optional[str] = Field(default=None)

    @field_validator("snap_revision", "workload_version", "state", mode="before")
    @classmethod
    def coerce_to_str(cls, v):
        """Coerce numeric values stored in the databag to str."""
        if v is None:
            return None
        return str(v)


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


class OpenSearchServerPeerModel(PeerModel):
    """Peer model mapping to the OpenSearch unit (server) state."""

    # Performance profile ("testing"/"production") applied to this unit's JVM/OpenSearch config.
    # None means "not yet set" — callers (e.g. ProfileManager.profile, OpenSearchServer.profile)
    # rely on this being falsy to fall back to the profile configured via charm config.
    profile: Optional[PerformanceType] = Field(default=None)
    # Whether this unit was one of the initial seed nodes used to bootstrap the cluster.
    # Alias pinned to the v0 databag key (no hyphenation) so upgraded units don't leave behind
    # a stale duplicate under the old key.
    bootstrap_contributor: bool = Field(default=False, alias="bootstrap_contributor")
    # Whether this unit has been removed from the cluster_manager-eligible role (e.g. scale-down).
    cluster_manager_removed: bool = Field(default=False, alias="cluster_manager_removed")
    # Timestamp (str(time.time())) set once the unit's OpenSearch service has started; empty
    # string means "not started". Used elsewhere as a truthy started/not-started flag.
    started: str = Field(default="")
    # Whether this unit is currently mid CA-rotation (new CA generated but not yet fully rolled).
    tls_ca_renewing: bool = Field(default=False, alias="tls_ca_renewing")
    # Whether this unit has finished renewing to the new CA.
    tls_ca_renewed: bool = Field(default=False, alias="tls_ca_renewed")
    # Whether this unit's TLS certificates (transport/HTTP) are fully configured.
    tls_configured: bool = Field(default=False, alias="tls_configured")
    # Last time this unit's databag was updated; used to force relation-changed observers to
    # notice a change even when no other field differs.
    update_ts: str = Field(default="")
    # Timestamp of the last time this unit checked its certificates for upcoming expiry.
    certs_exp_checked_at: str = Field(default="1970-01-01 00:00:00", alias="certs_exp_checked_at")
    # Allocation-exclusion entries (node names/IDs) this unit still needs to remove from the
    # cluster's shard allocation exclusion settings.
    allocation_exclusions_to_delete: list[str] = Field(default_factory=list)
    # Voting-exclusion entries this unit still needs to remove from the cluster's voting config.
    delete_voting_exclusions: list[str] = Field(default_factory=list)
    # Last known IP address of this unit; used to detect IP changes across reconciliation.
    last_host_ip: str = Field(default="", alias="last_host_ip")
    # Plugin configuration/cleanup metadata this unit is responsible for, keyed by plugin label.
    plugin_config_info: dict[str, PluginConfigInfo] = Field(
        default_factory=dict, alias="plugin_config_info"
    )
    # OAuth OpenID Connect URL configured on this unit (if an oauth relation is active).
    oauth_openid_connect_url: str = Field(default="", alias="oauth_openid_connect_url")
    # Set when this specific unit is departing/scaling down (as opposed to a related app or an
    # external relation being removed). Used to skip relation-broken side effects triggered by
    # the unit's own removal.
    unit_dying: bool = Field(default=False)
    # PID of this unit's running pebble-observer subprocess, or None if not started/stopped.
    pebble_observer_pid: Optional[int] = Field(default=None)

    @field_serializer("plugin_config_info")
    def _sort_plugin_config_info(self, value: dict) -> dict:
        return _sort_nested_dicts(value)

    # Transport TLS Secrets (node-to-node/transport layer; grouped under the "unit-transport"
    # secret group so they're stored as a single Juju secret rather than plaintext).
    transport_key: TransportSecretStr = Field(default="")  # Private key (PEM).
    transport_key_password: TransportSecretStr = Field(default="")  # Password for the key.
    transport_csr: TransportSecretStr = Field(default="")  # Certificate signing request.
    transport_chain: TransportSecretStr = Field(default="")  # Full certificate chain.
    transport_cert: TransportSecretStr = Field(default="")  # Signed leaf certificate.
    transport_ca_cert: TransportSecretStr = Field(default="")  # CA certificate.
    # Password protecting the transport truststore (holds trusted CA certs).
    transport_truststore_password: TransportSecretStr = Field(default="")
    transport_subject: TransportSecretStr = Field(default="")  # Certificate subject/DN.
    # Password protecting the transport keystore (holds the unit's private key/cert).
    transport_keystore_password: TransportSecretStr = Field(default="")

    # HTTP TLS Secrets (client-facing REST layer; grouped under the "unit-http" secret group).
    # Password protecting the HTTP keystore.
    http_keystore_password: HttpSecretStr = Field(default="")
    http_key: HttpSecretStr = Field(default="")  # Private key (PEM).
    http_key_password: HttpSecretStr = Field(default="")  # Password for the key.
    http_csr: HttpSecretStr = Field(default="")  # Certificate signing request.
    http_chain: HttpSecretStr = Field(default="")  # Full certificate chain.
    http_cert: HttpSecretStr = Field(default="")  # Signed leaf certificate.
    http_ca_cert: HttpSecretStr = Field(default="")  # CA certificate.
    # Password protecting the HTTP truststore.
    http_truststore_password: HttpSecretStr = Field(default="")
    http_subject: HttpSecretStr = Field(default="")  # Certificate subject/DN.

    @field_validator("allocation_exclusions_to_delete", "delete_voting_exclusions", mode="before")
    @classmethod
    def parse_comma_separated_strings(cls, v):
        """Validator for allocation_exclusions_to_delete, delete_voting_exclusions"""
        if isinstance(v, str):
            return list(filter(None, v.split(",")))
        return v

    @field_serializer("allocation_exclusions_to_delete", "delete_voting_exclusions")
    def serialize_comma_separated_strings(self, v: list[str]) -> str:
        """Validator for allocation_exclusions_to_delete, delete_voting_exclusions"""
        return ",".join(v)

    @field_validator("started", "update_ts", mode="before")
    @classmethod
    def coerce_to_str(cls, v):
        """Ensure fields is always a string, even if the databag returns a float/int."""
        if v is None:
            return ""
        return str(v)


class OpenSearchAppPeerModel(PeerModel):
    """Peer model mapping to the OpenSearch application state."""

    # Whether the internal "admin" user has been created in the security index.
    # Alias pinned to the v0 databag key (no hyphenation) so upgraded units don't leave behind
    # a stale duplicate under the old key.
    admin_user_initialized: bool = Field(default=False, alias="admin_user_initialized")
    # Number of units that took part in the initial cluster bootstrap (seed nodes).
    bootstrap_contributors_count: int = Field(default=0, alias="bootstrap_contributors_count")
    # Whether the OpenSearch security plugin's security index has been initialized.
    security_index_initialised: bool = Field(default=False, alias="security_index_initialised")
    # Cluster topology: unit name -> Node (roles, temperature, unit number) for every unit
    # in this application.
    nodes_config: dict[str, Node] = Field(default_factory=dict, alias="nodes_config")
    # Whether the application-level cluster bootstrap process has completed.
    bootstrapped: bool = Field(default=False)
    # Description of this application's role/config within the (possibly multi-app) deployment.
    deployment_description: DeploymentDescription | None = Field(default=None)
    # Peer-cluster fleet apps discovered locally by this application, keyed by app id.
    cluster_fleet_apps: dict[str, PeerClusterApp] = Field(
        default_factory=dict, alias="cluster_fleet_apps"
    )
    # Peer-cluster fleet apps as learned through peer-cluster relations (from other apps in the
    # fleet), keyed by app id.
    cluster_fleet_apps_rels: dict[str, PeerClusterApp] = Field(
        default_factory=dict, alias="cluster_fleet_apps_rels"
    )
    # Which app(s) in the fleet act as the main/failover orchestrator.
    orchestrators: Optional[PeerClusterOrchestrators] = Field(
        default_factory=PeerClusterOrchestrators
    )
    # Name of the first unit in this application to take on the "data" role.
    first_data_node: str = Field(default="", alias="first_data_node")
    # Last time this application's databag was updated; used to force relation-changed observers
    # to notice a change even when no other field differs.
    update_ts: str = Field(default="")
    # Voting-exclusion entries this application still needs to remove from the cluster's voting
    # config.
    delete_voting_exclusions: list[str] = Field(default_factory=list)
    # Allocation-exclusion entries this application still needs to remove from the cluster's
    # shard allocation exclusion settings.
    allocation_exclusions_to_delete: list[str] = Field(default_factory=list)
    # Users created for external client relations: username -> owning relation id.
    client_relation_users: dict[str, str] = Field(
        default_factory=dict, alias="client_relation_users"
    )
    # Whether the application is missing a relation it requires (e.g. a configured plugin or
    # backup relation that hasn't been related yet).
    missing_relations: bool = Field(default=False, alias="missing_relations")

    # Users (internal-user credentials, grouped under the "user" secret group).
    admin_password: UserSecretStr = Field(default="")
    admin_hashed_password: UserSecretStr = Field(default="")
    kibana_server_password: UserSecretStr = Field(default="")
    kibana_server_hashed_password: UserSecretStr = Field(default="")
    cos_password: UserSecretStr = Field(default="")
    cos_hashed_password: UserSecretStr = Field(default="")
    # Reserved slot in the "user" secret group for additional relation-user passwords.
    # Currently unset/unused by any manager or event handler.
    user_passwords: UserSecretStr = Field(default="")

    # Plugins
    # Plugin configuration/cleanup metadata this application is responsible for, keyed by
    # plugin label.
    plugin_config_info: dict[str, PluginConfigInfo] = Field(
        default_factory=dict, alias="plugin_config_info"
    )
    # JSON blob of per-plugin secrets (e.g. API keys) for plugins configured on this application.
    plugin_secrets: PluginsSecretStr = Field(default="")

    # Object Storage (cached copies of the S3/Azure/GCS relation data, propagated to the
    # peer-cluster fleet so non-orchestrator apps can reach the shared backup storage).
    s3: Optional[S3RelData] = Field(default=None)
    azure: Optional[AzureRelData] = Field(default=None)
    gcs: Optional[GcsRelData] = Field(default=None)

    # Admin TLS Secrets (used for admin/inter-cluster authentication to the security plugin;
    # grouped under the "app-admin" secret group).
    admin_truststore_password: AdminSecretStr = Field(default="")  # Truststore password.
    admin_subject: AdminSecretStr = Field(default="")  # Certificate subject/DN.
    admin_keystore_password: AdminSecretStr = Field(default="")  # Keystore password.
    admin_key: AdminSecretStr = Field(default="")  # Private key (PEM).
    admin_key_password: AdminSecretStr = Field(default="")  # Password for the key.
    admin_csr: AdminSecretStr = Field(default="")  # Certificate signing request.
    admin_chain: AdminSecretStr = Field(default="")  # Full certificate chain.
    admin_cert: AdminSecretStr = Field(default="")  # Signed leaf certificate.
    admin_ca_cert: AdminSecretStr = Field(default="")  # CA certificate.

    @field_validator("allocation_exclusions_to_delete", "delete_voting_exclusions", mode="before")
    @classmethod
    def parse_comma_separated_strings(cls, v):
        """Validator for allocation_exclusions_to_delete, delete_voting_exclusions"""
        if isinstance(v, str):
            return list(filter(None, v.split(",")))
        return v

    @field_serializer("allocation_exclusions_to_delete", "delete_voting_exclusions")
    def serialize_comma_separated_strings(self, v: list[str]) -> str:
        """Validator for allocation_exclusions_to_delete, delete_voting_exclusions"""
        return ",".join(v)

    @field_serializer(
        "nodes_config",
        "cluster_fleet_apps",
        "cluster_fleet_apps_rels",
        "client_relation_users",
        "plugin_config_info",
    )
    def _sort_dict_fields(self, value: dict) -> dict:
        return _sort_nested_dicts(value)

    @field_validator("update_ts", mode="before")
    @classmethod
    def coerce_to_str(cls, v):
        """Ensure 'fields' is always a string, even if the databag returns a float/int."""
        if v is None:
            return ""
        return str(v)

    @model_serializer(mode="wrap")
    def serialize_model(self, handler, info):
        """Serializes the model, but skip empty backups data"""
        data = PeerModel.serialize_model(self, handler, info)
        for field in ("s3", "azure", "gcs"):
            if data.get(field) is None:
                data.pop(field, None)
        return data


class PeerClusterAppModel(BaseCommonModel):
    """Pydantic model for peer cluster application-level databag.

    Inherits from BaseCommonModel so that secret fields are stored as Juju Secret URIs
    in the relation databag and automatically granted to remote applications, enabling
    cross-cluster (cross-application) sharing.
    """

    # Orchestration fields
    is_candidate_failover_orchestrator: bool = Field(default=False)
    trigger: str = Field(default="")
    main_orchestrator_registered: Optional[bool] = Field(default=None)
    cluster_fleet_apps: dict[str, PeerClusterApp] = Field(default_factory=dict)
    orchestrators: Optional[PeerClusterOrchestrators] = Field(
        default_factory=PeerClusterOrchestrators
    )
    s3: Optional[S3RelData] = Field(default=None)
    azure: Optional[AzureRelData] = Field(default=None)
    gcs: Optional[GcsRelData] = Field(default=None)
    rel_data_hash: str = Field(default="")
    error_data: Optional[PeerClusterRelErrorData] = Field(default=None)
    security_index_initialised: bool = Field(default=False)
    first_data_node: str = Field(default="")

    # App-state fields from OpenSearchAppPeerModel, shared cross-cluster
    cluster_name: str = Field(default="")
    nodes_config: dict[str, Node] = Field(default_factory=dict)
    deployment_description: Optional[DeploymentDescription] = Field(default=None)
    plugin_config_info: dict[str, PluginConfigInfo] = Field(default_factory=dict)

    # User secrets
    admin_password: UserSecretStr = Field(default="")
    admin_hashed_password: UserSecretStr = Field(default="")
    kibana_server_password: UserSecretStr = Field(default="")
    kibana_server_hashed_password: UserSecretStr = Field(default="")
    cos_password: UserSecretStr = Field(default="")
    cos_hashed_password: UserSecretStr = Field(default="")

    # Plugin secrets
    plugin_secrets: PluginsSecretStr = Field(default="")

    # Admin TLS secrets
    admin_truststore_password: AdminSecretStr = Field(default="")
    admin_subject: AdminSecretStr = Field(default="")
    admin_keystore_password: AdminSecretStr = Field(default="")
    admin_key: AdminSecretStr = Field(default="")
    admin_key_password: AdminSecretStr = Field(default="")
    admin_csr: AdminSecretStr = Field(default="")
    admin_chain: AdminSecretStr = Field(default="")
    admin_cert: AdminSecretStr = Field(default="")
    admin_ca_cert: AdminSecretStr = Field(default="")

    @field_serializer("cluster_fleet_apps", "nodes_config", "plugin_config_info")
    def _sort_dict_fields(self, value: dict) -> dict:
        return _sort_nested_dicts(value)

    @field_validator(
        "main_orchestrator_registered",
        "trigger",
        "rel_data_hash",
        "first_data_node",
        mode="before",
    )
    @classmethod
    def coerce_to_str(cls, v):
        """Ensure fields are always strings, even if the databag parses them as bool/float/int."""
        if v is None:
            return ""
        return str(v)

    @model_serializer(mode="wrap")
    def serialize_model(self, handler, info):
        """Serializes the model, but skip empty backups data"""
        if info.context and info.context.get("skip_secrets"):
            data = handler(self)
        else:
            data = BaseCommonModel.serialize_model(self, handler, info)
        for field in ("s3", "azure", "gcs"):
            if data.get(field) is None:
                data.pop(field, None)
        return data
