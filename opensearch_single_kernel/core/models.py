#!/usr/bin/env python3

# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

"""Collection of models used for the operation of the charm."""

import base64
import binascii
import json
import logging
import re
from abc import ABC, abstractmethod
from datetime import datetime
from hashlib import md5
from typing import Any, Iterator, Literal

from pydantic import BaseModel, Field, RootModel, model_validator, validator

from opensearch_single_kernel.common.constants import (
    _1GB_IN_KB,
    AZURE_CREDENTIALS,
    GCS_CREDENTIALS,
    MAX_HEAP_SIZE_IN_KB,
    S3_CREDENTIALS,
    DeploymentType,
    Directive,
    PerformanceType,
    StartMode,
    State,
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

    @model_validator(mode="before")
    @classmethod
    def set_props(cls, values):  # noqa: N805
        """Generate the attributes depending on the input."""
        if None not in list(values.values()):
            return values

        if not values.get("id") and None in [values.get("name"), values.get("model_uuid")]:
            raise ValueError("'id' or 'name and model_uuid' must be set.")

        if values.get("id"):
            full_id_split = values["id"].split("/")
            values["name"], values["model_uuid"] = full_id_split[-1], full_id_split[0]
        else:
            values["id"] = f"{values['model_uuid']}/{values['name']}"

        values["short_id"] = md5(values["id"].encode()).hexdigest()[:3]
        return values


class Node(Model):
    """Data class representing a node in a cluster."""

    name: str
    roles: list[str]
    ip: str
    app: App
    unit_number: int
    temperature: str | None = None

    @classmethod
    @validator("roles")
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

    @model_validator(mode="before")
    @classmethod
    def set_node_temperature(cls, values):  # noqa: N805
        """Set and validate the node temperature."""
        allowed_temps = ["hot", "warm", "cold", "frozen", "content"]

        input_temps = set()
        for role in values.get("roles", []):
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
            values["data_temperature"] = temperature
            if not values.get("roles", []):
                values["roles"] = []
            values["roles"].append("data")
            values["roles"].remove(f"data.{temperature}")
            values["roles"] = list(set(values["roles"]))

        return values


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

    @model_validator(mode="before")
    @classmethod
    def prevent_none(cls, values):  # noqa: N805
        """Validate the message or lack of depending on the state."""
        if values.get("value") == State.ACTIVE:
            values["message"] = ""
        elif not values.get("message", "").strip():
            raise ValueError("The message must be set when state not Active.")

        return values


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

    @model_validator(mode="before")
    @classmethod
    def set_promotion_time(cls, values):  # noqa: N805
        """Set promotion time of a failover to a main CM."""
        if (
            not values.get("promotion_time")
            and values.get("typ") == DeploymentType.MAIN_ORCHESTRATOR
        ):
            values["promotion_time"] = datetime.now().timestamp()

        return values


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
                int(self.memory_requirements.jvm_heap_percentage * mem_size), MAX_HEAP_SIZE_IN_KB
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


# --- Backup related models ---
class S3RelDataCredentials(Model):
    """Model class for credentials passed on the s3 relation."""

    access_key: str = Field(alias="access-key", default=None)
    secret_key: str = Field(alias="secret-key", default=None)
    s3_tls_ca_chain: str | list[str] | None = Field(default=None, alias="s3-tls-ca-chain")

    class Config:
        """Model config of this pydantic model."""

        validate_by_name = True


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

    class Config:
        """Model config of this pydantic model."""

        validate_by_name = True

    @model_validator(mode="before")
    @classmethod
    def validate_core_fields(cls, values):  # noqa: N805
        """Validate the core fields of the S3 relation data."""
        if (
            not (s3_creds := values.get("credentials"))
            or not s3_creds.access_key
            or not s3_creds.secret_key
        ):
            raise ValueError("Missing fields: access_key, secret_key")

        # NOTE: Both bucket and endpoint must be set. If none of them are set,
        # but credentials were found, this likely means that we are validating for a
        # non cluster_manager application, which only needs credentials.
        if values.get("bucket") and not values.get("endpoint"):
            raise ValueError("Missing field: endpoint")
        if values.get("endpoint") and not values.get("bucket"):
            raise ValueError("Missing field: bucket")
        if not values.get("region"):
            raise ValueError("Missing field: region")

        # remove any duplicate, prefix or trailing "/" characters
        if base_path := values.get("base_path"):
            base_path = re.sub(r"/+", "/", base_path).strip().strip("/")
        values["base_path"] = base_path or None

        return values

    @validator("tls_ca_chain", pre=True)
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

    @validator("path_style_access", pre=True)
    def change_path_style_type(cls, value) -> bool:  # noqa: N805
        """Coerce a type change of the path_style_access into a bool."""
        if isinstance(value, str):
            return value.lower() == "path"
        return bool(value)

    @validator(S3_CREDENTIALS, check_fields=False)
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

    storage_account: str = Field(alias="storage-account", default=None)
    secret_key: str = Field(alias="secret-key", default=None)

    class Config:
        """Model config of this pydantic model."""

        validate_by_name = True


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

    class Config:
        """Model config of this pydantic model."""

        validate_by_name = True

    @model_validator(mode="before")
    @classmethod
    def validate_core_fields(cls, values):  # noqa: N805
        """Validate the core fields of the azure relation data."""
        if (
            not (creds := values.get("credentials"))
            or not creds.storage_account
            or not creds.secret_key
        ):
            raise ValueError("Missing fields: storage_account, secret_key")

        # remove any duplicate, prefix or trailing "/" characters
        if base_path := values.get("base_path"):
            base_path = re.sub(r"/+", "/", base_path).strip().strip("/")
        values["base_path"] = base_path or None

        return values

    @validator(AZURE_CREDENTIALS, check_fields=False)
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

    class Config:
        """Model config of this pydantic model."""

        validate_by_name = True

    @validator("secret_key", pre=True)
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

    class Config:
        """Model config of this pydantic model."""

        validate_by_name = True

    @model_validator(mode="before")
    @classmethod
    def validate_core_fields(cls, values):  # noqa: N805
        """Validate the core fields of the gcs relation data."""
        creds = values.get("credentials")
        if not creds or not creds.secret_key:
            raise ValueError("Missing fields: secret-key")

        if not values.get("bucket"):
            raise ValueError("Missing field: bucket")

        # remove any duplicate, prefix or trailing "/" characters
        if base_path := values.get("base_path"):
            base_path = re.sub(r"/+", "/", base_path).strip().strip("/")
        values["base_path"] = base_path or None

        return values

    @validator(GCS_CREDENTIALS, check_fields=False)
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


class ObjectStorageConfig(Model):
    """Model class for the object storage config - for all clouds."""

    s3: S3RelData | None = None
    azure: AzureRelData | None = None
    gcs: GcsRelData | None = None
