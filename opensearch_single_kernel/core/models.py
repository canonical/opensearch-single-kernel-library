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
from typing import Any, Iterator, Literal

import poetry.core.constraints.version as poetry_version
from data_platform_helpers.advanced_statuses import StatusObject
from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    RootModel,
    field_validator,
    model_validator,
)

from opensearch_single_kernel.common.constants import (
    _1GB_IN_KB,
    ADMIN_USER,
    AZURE_CREDENTIALS,
    COS_USER,
    GCS_CREDENTIALS,
    KIBANA_SERVER_USER,
    MAX_HEAP_SIZE_IN_KB,
    S3_CREDENTIALS,
    DeploymentType,
    Directive,
    PerformanceType,
    SmtpTransportSecurity,
    StartMode,
    State,
)
from opensearch_single_kernel.common.statuses import PeerClusterErrorDataStatuses
from opensearch_single_kernel.utils.enum import BaseStrEnum

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
            self.cleanup[key] = sorted(list(set(current) | set(items)))


# --- Backup related models ---
class S3RelDataCredentials(Model):
    """Model class for credentials passed on the s3 relation."""

    access_key: str = Field(alias="access-key", default="")
    secret_key: str = Field(alias="secret-key", default="")
    s3_tls_ca_chain: str | list[str] | None = Field(default=None, alias="s3-tls-ca-chain")

    model_config = ConfigDict(populate_by_name=True)


class S3RelData(Model):
    """Model class for the S3 relation data.

    This model should receive the data directly from the relation and map it to a model.
    """

    bucket: str = Field(default="")
    endpoint: str = Field(default="")
    region: str = Field(default="")
    base_path: str | None = Field(alias="path", default=None)
    protocol: str | None = None
    storage_class: str | None = Field(alias="storage-class", default=None)
    tls_ca_chain: str | list[str] | None = Field(default=None, alias="tls-ca-chain")
    credentials: S3RelDataCredentials = Field(alias=S3_CREDENTIALS)
    path_style_access: bool = Field(alias="s3-uri-style", default=False)

    model_config = ConfigDict(populate_by_name=True)

    @model_validator(mode="after")
    def validate_core_fields(self):
        """Validate the core fields of the S3 relation data."""
        if (
            not (self.credentials)
            or not self.credentials.access_key
            or not self.credentials.secret_key
        ):
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

        # remove any duplicate, prefix or trailing "/" characters
        if base_path := self.base_path:
            base_path = re.sub(r"/+", "/", base_path).strip().strip("/")
        self.base_path = base_path or None

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

    @field_validator("path_style_access", mode="before")
    def change_path_style_type(cls, value) -> bool:  # noqa: N805
        """Coerce a type change of the path_style_access into a bool."""
        if isinstance(value, str):
            return value.lower() == "path"
        return bool(value)

    @field_validator(S3_CREDENTIALS, mode="before", check_fields=False)
    def ensure_secret_content(cls, conf: dict[str, str] | S3RelDataCredentials):  # noqa: N805
        """Ensure the secret content is set."""
        if not conf:
            return None

        data = conf
        if isinstance(conf, dict):
            # We are
            data = S3RelDataCredentials.from_dict(conf)

        for value in data.dict().values():
            if value.startswith("secret://"):
                raise ValueError(f"The secret content must be passed, received {value} instead")
        return data

    @staticmethod
    def get_endpoint_protocol(endpoint: str) -> str:
        """Returns the protocol based on the endpoint."""
        if not endpoint:
            return "https"

        if endpoint.startswith("http://"):
            return "http"
        return "https"

    @classmethod
    def from_relation(cls, input_dict: dict[str, Any] | None):
        """Create a new instance of this class from a json/dict repr.

        This method creates a nested S3RelDataCredentials object from the input dict.
        """
        if not input_dict:
            return cls()

        creds = S3RelDataCredentials(**input_dict)
        protocol = S3RelData.get_endpoint_protocol(input_dict.get("endpoint"))
        return cls.from_dict(
            dict(input_dict) | {"protocol": protocol, S3_CREDENTIALS: creds.dict()}
        )


class AzureRelDataCredentials(Model):
    """Model class for credentials passed on the Azure relation."""

    storage_account: str = Field(alias="storage-account", default="")
    secret_key: str = Field(alias="secret-key", default="")

    model_config = ConfigDict(populate_by_name=True)


class AzureRelData(Model):
    """Model class for the Azure relation data.

    This model should receive the data directly from the relation and map it to a model.
    """

    storage_account: str = Field(alias="storage-account", default="")
    container: str = Field(default="")
    endpoint: str | None = Field(default="")
    base_path: str | None = Field(alias="path", default=None)
    connection_protocol: str | None = Field(alias="connection-protocol", default=None)
    credentials: AzureRelDataCredentials = Field(
        alias=AZURE_CREDENTIALS, default=AzureRelDataCredentials()
    )

    model_config = ConfigDict(populate_by_name=True)

    @model_validator(mode="after")
    def validate_core_fields(self):  # noqa: N805
        """Validate the core fields of the azure relation data."""
        if (
            not (self.credentials)
            or not self.credentials.storage_account
            or not self.credentials.secret_key
        ):
            raise ValueError("Missing fields: storage_account, secret_key")

        # remove any duplicate, prefix or trailing "/" characters
        if base_path := self.base_path:
            base_path = re.sub(r"/+", "/", base_path).strip().strip("/")
        self.base_path = base_path or None

        return self

    @field_validator(AZURE_CREDENTIALS, mode="before", check_fields=False)
    def ensure_secret_content(cls, conf: dict[str, str] | AzureRelDataCredentials):  # noqa: N805
        """Ensure the secret content is set."""
        if not conf:
            return None

        data = conf
        if isinstance(conf, dict):
            data = AzureRelDataCredentials.from_dict(conf)

        for value in data.dict().values():
            if value.startswith("secret://"):
                raise ValueError(f"The secret content must be passed, received {value} instead")
        return data

    @classmethod
    def from_relation(cls, input_dict: dict[str, Any] | None):
        """Create a new instance of this class from a json/dict repr.

        This method creates a nested AzureRelDataCredentials object from the input dict.
        """
        if not input_dict:
            return cls()

        creds = AzureRelDataCredentials(**input_dict)
        return cls.from_dict(dict(input_dict) | {AZURE_CREDENTIALS: creds.dict()})


class GcsRelDataCredentials(Model):
    """Model class for credentials passed on the gcs relation."""

    secret_key: str | None = Field(alias="secret-key", default=None)
    model_config = ConfigDict(populate_by_name=True)

    @field_validator("secret_key", mode="before")
    def _normalize_secret_key(cls, values):  # noqa: N805
        """Accept either raw JSON or base64-encoded JSON"""
        if values is None:
            return None

        content = values.decode() if isinstance(values, (bytes, bytearray)) else str(values)
        if not (content := content.strip()):
            return None

        # already JSON
        if content.startswith("{") and content.endswith("}"):
            # validate JSON shape
            json.loads(content)
            return content

        # base64 (urlsafe)
        try:
            decoded_bytes = base64.b64decode(content, altchars=b"-_", validate=True)
            decoded_text = decoded_bytes.decode("utf-8").strip()
            json.loads(decoded_text)
            return decoded_text
        except (binascii.Error, ValueError, UnicodeDecodeError, json.JSONDecodeError) as e:
            raise ValueError("secret-key is not valid JSON (raw or base64-encoded)") from e


class GcsRelData(Model):
    """Model class for the GCS relation data.

    This model should receive the data directly from the relation and map it to a model.
    """

    bucket: str = Field(default="")
    base_path: str | None = Field(alias="path", default=None)
    storage_class: str | None = Field(alias="storage-class", default=None)
    credentials: GcsRelDataCredentials = Field(
        alias=GCS_CREDENTIALS, default_factory=GcsRelDataCredentials
    )
    model_config = ConfigDict(populate_by_name=True)

    @model_validator(mode="after")
    def validate_core_fields(self):
        """Validate the core fields of the gcs relation data."""
        if not self.credentials or not self.credentials.secret_key:
            raise ValueError("Missing fields: secret-key")

        if not self.bucket:
            raise ValueError("Missing field: bucket")

        # remove any duplicate, prefix or trailing "/" characters
        if base_path := self.base_path:
            base_path = re.sub(r"/+", "/", base_path).strip().strip("/")
        self.base_path = base_path or None

        return self

    @field_validator(GCS_CREDENTIALS, mode="before", check_fields=False)
    def ensure_secret_content(cls, conf: dict[str, str] | GcsRelDataCredentials):  # noqa: N805):
        """Ensure the secret content is set."""
        if not conf:
            return None

        data = conf if isinstance(conf, dict) else conf.dict(by_alias=True, exclude_none=True)
        for v in data.values():
            if isinstance(v, str) and v.startswith("secret://"):
                raise ValueError(f"The secret content must be passed, received {v} instead")
        return conf

    @classmethod
    def from_relation(cls, input_dict: dict[str, Any] | None):
        """Create a new instance of this class from a json/dict repr.

        This method creates a nested GcsRelDataCredentials object from the input dict.
        """
        if not input_dict:
            return None
        creds = GcsRelDataCredentials(**input_dict)
        merged = {**input_dict}
        merged[GCS_CREDENTIALS] = creds.dict(by_alias=True, exclude_none=True)
        return cls.parse_obj(merged)


ObjectStorageCredentials = S3RelDataCredentials | AzureRelDataCredentials | GcsRelDataCredentials


class ObjectStorageConfig(Model):
    """Model class for the object storage config - for all clouds."""

    s3: S3RelData | None = None
    azure: AzureRelData | None = None
    gcs: GcsRelData | None = None


# Peer cluster
class PeerClusterRelDataCredentials(Model):
    """Model class for credentials passed on the PCluster relation."""

    admin_username: str
    admin_password: str
    admin_password_hash: str
    kibana_password: str
    kibana_password_hash: str
    monitor_password: str | None
    admin_tls: dict[str, str | None] | None
    s3: S3RelDataCredentials | None
    azure: AzureRelDataCredentials | None
    gcs: GcsRelDataCredentials | None


class PeerClusterRelData(Model):
    """Model class for the PCluster relation data."""

    cluster_name: str
    cm_nodes: list[Node]
    credentials: PeerClusterRelDataCredentials
    deployment_desc: DeploymentDescription | None
    security_index_initialised: bool = False
    first_data_node: str | None = None
    plugins: dict[str, PluginConfigInfo] | None = None

    @staticmethod
    def peer_cluster_rel_data_from_str(
        secrets, redacted_dict_str: str, peek_secrets: bool = False
    ):
        """Construct the peer cluster rel data from the secret data."""
        content = json.loads(redacted_dict_str)
        credentials = content["credentials"]

        credentials["admin_password"] = secrets.resolve_credential(
            credentials["admin_password"], password_key=ADMIN_USER, peek_secrets=peek_secrets
        )
        credentials["admin_password_hash"] = secrets.resolve_credential(
            credentials["admin_password_hash"], hash_key=ADMIN_USER, peek_secrets=peek_secrets
        )

        credentials["kibana_password"] = secrets.resolve_credential(
            credentials["kibana_password"],
            password_key=KIBANA_SERVER_USER,
            peek_secrets=peek_secrets,
        )
        credentials["kibana_password_hash"] = secrets.resolve_credential(
            credentials["kibana_password_hash"],
            hash_key=KIBANA_SERVER_USER,
            peek_secrets=peek_secrets,
        )

        if credentials.get("monitor_password"):
            credentials["monitor_password"] = secrets.resolve_credential(
                credentials["monitor_password"], password_key=COS_USER, peek_secrets=peek_secrets
            )
        else:
            credentials["monitor_password"] = None

        if credentials.get("admin_tls") and isinstance(credentials["admin_tls"], str):
            credentials["admin_tls"] = secrets.resolve_credential(
                credentials["admin_tls"], peek_secrets=peek_secrets
            )
        else:
            credentials["admin_tls"] = None

        if (
            credentials.get("s3")
            and credentials["s3"].get("access-key")
            and credentials["s3"].get("secret-key")
        ):
            credentials["s3"]["access-key"] = secrets.resolve_credential(
                credentials["s3"]["access-key"],
                content_key="s3-access-key",
                peek_secrets=peek_secrets,
            )
            credentials["s3"]["secret-key"] = secrets.resolve_credential(
                credentials["s3"]["secret-key"],
                content_key="s3-secret-key",
                peek_secrets=peek_secrets,
            )
            if credentials["s3"].get("s3-tls-ca-chain"):
                credentials["s3"]["s3-tls-ca-chain"] = secrets.resolve_credential(
                    credentials["s3"]["s3-tls-ca-chain"],
                    content_key="s3-tls-ca-chain",
                    peek_secrets=peek_secrets,
                )
        else:
            credentials["s3"] = {}
        if (
            credentials.get("azure")
            and credentials["azure"].get("storage-account")
            and credentials["azure"].get("secret-key")
        ):
            credentials["azure"]["storage-account"] = secrets.resolve_credential(
                credentials["azure"]["storage-account"],
                content_key="azure-storage-account",
                peek_secrets=peek_secrets,
            )
            credentials["azure"]["secret-key"] = secrets.resolve_credential(
                credentials["azure"]["secret-key"],
                content_key="azure-secret-key",
                peek_secrets=peek_secrets,
            )
        else:
            credentials["azure"] = {}

        if credentials.get("gcs", {}).get("secret-key"):
            credentials["gcs"]["secret-key"] = secrets.resolve_credential(
                credentials["gcs"]["secret-key"],
                content_key="gcs-secret-key",
                peek_secrets=peek_secrets,
            )
        else:
            credentials["gcs"] = {}

        return PeerClusterRelData.from_dict(content)


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


class JWTAuthConfiguration(Model):
    """Model class for the configuration parameters of JWT authentication."""

    signing_key: str
    jwt_header: str | None = None
    jwt_url_parameter: str | None = None
    roles_key: str
    subject_key: str | None = None
    required_audience: str | None = None
    required_issuer: str | None = None
    jwt_clock_skew_tolerance_seconds: int | None = None


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
