#!/usr/bin/env python3

# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

"""Collection of models defining state structure of OpenSearch charm, relations and units."""


import datetime
import enum
import json
from abc import ABC, abstractmethod
from ast import literal_eval
from hashlib import md5
from typing import Any, Dict, List, Literal, Optional, Union

from ops import Secret
from ops.model import Application, Relation, Unit
from overrides import override
from pydantic import BaseModel, Field, root_validator, validator
from pydantic.utils import ROOT_KEY

from opensearch_single_kernel.common.constants import (
    _1GB_IN_KB,
    MAX_HEAP_SIZE,
    PERFORMANCE_PROFILE,
    DeploymentType,
    Directive,
    PerformanceType,
    Scope,
    StartMode,
    State,
)
from opensearch_single_kernel.lib.charms.data_platform_libs.v0.data_interfaces import (
    Data,
    DataPeerData,
    DataPeerUnitData,
    ProviderData,
    RequirerData,
)
from opensearch_single_kernel.utils.logging import WithLogging


class Model(ABC, BaseModel):
    """Base model class."""

    def __init__(self, **data: Any) -> None:
        if self.__custom_root_type__ and data.keys() != {ROOT_KEY}:
            data = {ROOT_KEY: data}
        super().__init__(**data)

    def to_str(self, by_alias: bool = False) -> str:
        """Deserialize object into a string."""
        return json.dumps(Model.sort_payload(self.to_dict(by_alias=by_alias)))

    def to_dict(self, by_alias: bool = False) -> Dict[str, Any]:
        """Deserialize object into a dict."""
        return self.dict(by_alias=by_alias)

    @classmethod
    def from_dict(cls, input_dict: Optional[Dict[str, Any]]):
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


class DataStore(ABC):
    """Class representing a data store used in the OPs code of the charm."""

    def __init__(self, charm):
        self._charm = charm

    @abstractmethod
    def put(self, scope: Scope, key: str, value: Optional[any]) -> None:
        """Put string into the data store."""
        pass

    @abstractmethod
    def put_object(
        self, scope: Scope, key: str, value: Dict[str, any], merge: bool = False
    ) -> None:
        """Put object into the data store."""
        pass

    @abstractmethod
    def has(self, scope: Scope, key: str):
        """Check if the said key is contained in the store."""
        pass

    @abstractmethod
    def get(
        self, scope: Scope, key: str, default: Optional[Union[int, float, str, bool]] = None
    ) -> Optional[Union[int, float, str, bool]]:
        """Get string from the data store."""
        pass

    @abstractmethod
    def get_object(self, scope: Scope, key: str) -> Optional[Dict[str, any]]:
        """Get dict / json object from the data store."""
        pass

    @abstractmethod
    def delete(self, scope: Scope, key: str):
        """Delete object from the data store."""
        pass

    @staticmethod
    def cast(str_val: str) -> Union[bool, int, float, str]:
        """Cast a string to the corresponding primitive type."""
        try:
            typed_val = literal_eval(str_val.capitalize())
            if type(typed_val) not in {bool, int, float, str}:
                return str_val

            return typed_val
        except (ValueError, SyntaxError):
            return str_val

    @staticmethod
    def put_or_delete(data: Dict[str, str], key: str, value: Optional[str]):
        """Put data into the key/val data store or delete if value is None."""
        if value is None:
            data.pop(key, None)
            return

        data.update({key: str(value)})


class RelationDataStore(DataStore):
    """Class representing a relation data store for a charm."""

    def __init__(self, charm, relation_name: str):
        super(RelationDataStore, self).__init__(charm)
        self.relation_name = relation_name

    @override
    def put(self, scope: Scope, key: str, value: Optional[Union[any]]) -> None:
        """Put string into the relation data store."""
        if scope is None:
            raise ValueError("Scope undefined.")

        data = self._get_relation_data(scope)
        self.put_or_delete(data, key, value)

    @override
    def put_object(
        self, scope: Scope, key: str, value: Dict[str, any], merge: bool = False
    ) -> None:
        """Put dict / json object into relation data store."""
        if merge:
            stored = self.get_object(scope, key)

            if stored is not None:
                stored.update(value)
                value = stored

        sorted_value = Model.sort_payload(value)

        payload_str = None
        if value is not None:
            payload_str = json.dumps(
                sorted_value, default=RelationDataStore._default_encoder, sort_keys=True
            )

        self.put(scope, key, payload_str)

    @override
    def has(self, scope: Scope, key: str):
        """Check if the said key is contained in the relation data."""
        if scope is None:
            raise ValueError("Scope undefined.")

        return key in (self._get_relation_data(scope) or {})

    @override
    def get(
        self,
        scope: Scope,
        key: str,
        default: Optional[Union[int, float, str, bool]] = None,
        auto_casting: bool = True,
    ) -> Optional[Union[int, float, str, bool]]:
        """Get string from the relation data store."""
        if scope is None:
            raise ValueError("Scope undefined.")

        data = self._get_relation_data(scope)

        value = data.get(key)
        if value is None:
            return default

        if not auto_casting:
            return value

        return self.cast(value)

    @override
    def get_object(self, scope: Scope, key: str) -> Optional[Dict[str, any]]:
        """Get dict / json object from the relation data store."""
        data = self.get(scope, key)
        if data is None:
            return None

        return json.loads(data)

    @override
    def delete(self, scope: Scope, key: str):
        """Delete object from the relation data store."""
        self.put(scope, key, None)

    def _get_relation_data(self, scope: Scope) -> Dict[str, str]:
        """Relation data object."""
        relation = self._charm.model.get_relation(self.relation_name)
        if relation is None:
            return {}

        relation_scope = self._charm.app if scope == Scope.APP else self._charm.unit

        return relation.data.get(relation_scope)

    @staticmethod
    def _default_encoder(o: Any) -> Any:
        """Default encoder for json dumps."""
        if isinstance(o, enum.Enum):
            return o.value

        if hasattr(o, "__dict__"):
            return vars(o)

        raise TypeError(f"Unserializable {o.__class__.__name__}")


class App(Model):
    """Data class representing an application."""

    id: Optional[str] = None
    short_id: Optional[str] = None
    name: Optional[str] = None
    model_uuid: Optional[str] = None

    @root_validator
    def set_props(cls, values):  # noqa: N805
        """Generate the attributes depending on the input."""
        if None not in list(values.values()):
            return values

        if not values["id"] and None in [values["name"], values["model_uuid"]]:
            raise ValueError("'id' or 'name and model_uuid' must be set.")

        if values["id"]:
            full_id_split = values["id"].split("/")
            values["name"], values["model_uuid"] = full_id_split[-1], full_id_split[0]
        else:
            values["id"] = f"{values['model_uuid']}/{values['name']}"

        values["short_id"] = md5(values["id"].encode()).hexdigest()[:3]
        return values


class Node(Model):
    """Data class representing a node in a cluster."""

    name: str
    roles: List[str]
    ip: str
    app: App
    unit_number: int
    temperature: Optional[str] = None

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
    main_app: Optional[App]
    failover_rel_id: int = -1
    failover_app: Optional[App]

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
    roles: List[str]
    # We have a breaking change in the model
    # For older charms, this field will not exist and they will be set in the
    # profile called "testing".
    data_temperature: Optional[str] = None

    @root_validator
    def set_node_temperature(cls, values):  # noqa: N805
        """Set and validate the node temperature."""
        allowed_temps = ["hot", "warm", "cold", "frozen", "content"]

        input_temps = set()
        for role in values["roles"]:
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

            values["roles"].append("data")
            values["roles"].remove(f"data.{temperature}")
            values["roles"] = list(set(values["roles"]))

        return values


class PeerClusterApp(Model):
    """Model class for representing an application part of a large deployment."""

    app: App
    planned_units: int
    units: List[str]
    roles: List[str]


class PeerClusterFleetApps(Model):
    """Model class for all applications in a large deployment as a dict."""

    __root__: Dict[str, PeerClusterApp]

    def __iter__(self):
        """Implements the iter magic method."""
        return iter(self.__root__)

    def __getitem__(self, item):
        """Implements the getitem magic method."""
        return self.__root__[item]


class DeploymentState(Model):
    """Full state of a deployment, along with the juju status."""

    value: State
    message: str = Field(default="")

    @root_validator
    def prevent_none(cls, values):  # noqa: N805
        """Validate the message or lack of depending on the state."""
        if values["value"] == State.ACTIVE:
            values["message"] = ""
        elif not values["message"].strip():
            raise ValueError("The message must be set when state not Active.")

        return values


class DeploymentDescription(Model):
    """Model class describing the current state of a deployment / sub-cluster."""

    app: App
    config: PeerClusterConfig
    start: StartMode
    pending_directives: List[Directive]
    typ: DeploymentType
    state: DeploymentState = DeploymentState(value=State.ACTIVE)
    cluster_name_autogenerated: bool = False
    promotion_time: Optional[float]

    @root_validator
    def set_promotion_time(cls, values):  # noqa: N805
        """Set promotion time of a failover to a main CM."""
        if not values["promotion_time"] and values["typ"] == DeploymentType.MAIN_ORCHESTRATOR:
            values["promotion_time"] = datetime.now().timestamp()

        return values


class ProfileMemoryRequirements(Model):
    """Memory requirements for a profile"""

    memory_size: Optional[int] = None
    jvm_heap_percentage: Optional[float] = None


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
            return min(int(self.memory_requirements.jvm_heap_percentage * mem_size), MAX_HEAP_SIZE)
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


class RelationState(WithLogging):
    """Relation state object."""

    def __init__(
        self,
        relation: Relation | None,
        data_interface: Data,
        component: Unit | Application | None,
    ):
        self.relation = relation
        self.data_interface = data_interface
        self.unit = component
        self.relation_data = self.data_interface.as_dict(self.relation.id) if self.relation else {}

    def __bool__(self) -> bool:
        """Boolean evaluation based on the existence of self.relation."""
        try:
            return bool(self.relation)
        except AttributeError:
            return False

    def update(self, items: dict[str, str]) -> None:
        """Write to relation data."""
        if not self.relation:
            self.logger.warning(
                f"Fields {list(items.keys())} were attempted to be written on the relation before it exists."
            )
            return

        delete_fields = [key for key in items if not items[key]]
        update_content = {k: items[k] for k in items if k not in delete_fields}

        self.relation_data.update(update_content)

        for field in delete_fields:
            # use del instead of pop here because of error with dataplatform-libs
            try:
                del self.relation_data[field]
            except KeyError:
                pass


class PeerClusterOrchestratorData(ProviderData, RequirerData):
    """Orchestrator provider data model."""

    # This is to bypass the PrematureDataAccessError, which is irrelevant in this case.
    def _update_relation_data(self, relation: Relation, data: dict[str, str]) -> None:
        """Set values for fields not caring whether it's a secret or not."""
        super(ProviderData, self)._update_relation_data(relation, data)


class PeerClusterData(ProviderData, RequirerData):
    """Orchestrator requirer data model."""

    # This is to bypass the PrematureDataAccessError, which is irrelevant in this case.
    def _update_relation_data(self, relation: Relation, data: dict[str, str]) -> None:
        """Set values for fields not caring whether it's a secret or not."""
        super(ProviderData, self)._update_relation_data(relation, data)


class PeerCluster(RelationState):
    """State collection metadata for a peer-cluster application."""

    def __init__(self, relation, data_interface, component):
        super().__init__(relation, data_interface, component)


class OpenSearchServer(RelationState):
    """State/Relation data collection for an opensearch unit"""

    def __init__(
        self, relation: Relation | None, data_interface: DataPeerUnitData, component: Unit
    ):
        super().__init__(relation, data_interface, component)
        self.unit = component

    @property
    def unit_id(self) -> int:
        """The id of the unit from the unit name."""
        return int(self.unit.name.split("/")[1])

    @property
    def profile(self) -> Optional[OpenSearchProfile]:
        """Current profile of the unit"""
        if profile_str := self.relation_data.get(PERFORMANCE_PROFILE, None):
            return (
                ProductionProfile()
                if PerformanceType(profile_str) == PerformanceType.PRODUCTION
                else TestingProfile()
            )
        return None

    @property
    def unit_name(self) -> str:
        """The unit's name."""
        return self.unit.name

    @property
    def is_app_leader(self) -> bool:
        """Check if the current unit is the leader of the application."""
        return self.unit.is_leader()

    @property
    def bootstrap_contributor(self) -> bool:
        """Get value of 'bootstrap_contributor'"""
        return bool(self.relation.data.get("bootstrap_contributor", ""))

    @property
    def started(self) -> bool:
        """Get the value of 'started' key from unit data bag"""
        return bool(self.relation_data.get("started", ""))


class OpenSearchApplication(RelationState):
    """An OpenSearch Application is a charm application with a given role.

    In OpenSearch a cluster can be formed using one or more applications.
    This class defines state/relation data for a single opensearch application.
    """

    def __init__(
        self, relation: Relation | None, data_interface: DataPeerData, component: Application
    ):
        super().__init__(relation, data_interface, component)
        self.app = component

    @override
    def get_object(self, key: str) -> Optional[Dict[str, any]]:
        """Get dict / json object from the relation data store."""
        data = self.relation_data.get(key)
        if data is None:
            return None

        return json.loads(data)

    def put_object(self, key: str, value: Dict[str, any], merge: bool = False) -> None:
        """Put dict / json object into relation data store."""
        if merge:
            stored = self.get_object(key)

            if stored is not None:
                stored.update(value)
                value = stored

        sorted_value = Model.sort_payload(value)

        payload_str = None
        if value is not None:
            payload_str = json.dumps(
                sorted_value, default=RelationDataStore._default_encoder, sort_keys=True
            )

        self.update({key: payload_str})

    @property
    def name(self) -> str:
        """Return the name of the Application."""
        return self.app.name

    @property
    def is_admin_user_configured(self) -> bool:
        """Return the value of 'admin_user_initialized' in application state."""
        return self.relation_data.get("admin_user_initialized", "") == "True"

    @property
    def security_index_initialised(self) -> str:
        """Return the value of 'security_index_initialised' in application state"""
        return self.relation_data.get("security_index_initialised", "")

    @property
    def nodes_config(self) -> str:
        """Return the value of 'nodes_config' in application state"""
        return self.relation_data.get("nodes_config", "")

    @property
    def bootstrapped(self) -> bool:
        """Return the value of 'bootstrapped' in application state"""
        return bool(self.relation_data.get("bootstrapped", ""))

    @property
    def deployment_desc(self) -> Optional[DeploymentDescription]:
        """Return the deployment description object if any."""
        current_deployment_desc = self.relation_data.get("deployment-desciption")
        if not current_deployment_desc:
            return None
        else:
            current_deployment_desc = json.loads(current_deployment_desc)
            if not current_deployment_desc:
                return None

            return DeploymentDescription.from_dict(current_deployment_desc)

    @property
    def cluster_fleet_apps(self) -> Dict[str, PeerClusterApp]:
        """Get the cluster fleet applications."""
        cluster_fleet_apps = self.relation_data.get("cluster_fleet_apps", "")
        if not cluster_fleet_apps:
            cluster_fleet_apps = {}
        elif not json.loads(cluster_fleet_apps):
            cluster_fleet_apps = {}
        else:
            cluster_fleet_apps = json.loads(cluster_fleet_apps)
        return {id: PeerClusterApp.from_dict(app) for id, app in cluster_fleet_apps.items()}

    def apps_in_fleet(self) -> List[PeerClusterApp]:
        """Returns list of apps in cluster fleet"""
        cluster_fleet_apps = self.relation_data.get_object(Scope.APP, "cluster_fleet_apps", "")
        if not cluster_fleet_apps:
            cluster_fleet_apps = {}
        elif not json.loads(cluster_fleet_apps):
            cluster_fleet_apps = json.loads(cluster_fleet_apps)
        return [PeerClusterApp.from_dict(app) for app in cluster_fleet_apps.values()]


class SecretCache:
    """Internal helper class locally cache secrets.

    The data structure is precisely reusing/simulating as in the actual Secret Storage
    """

    CACHED_META = "meta"
    CACHED_CONTENT = "content"

    def __init__(self):
        # Structure:
        # NOTE: "objects" (i.e. dict-s) and scalar values are handled in a unified way
        # precisely as done for the Secret objects themselves.
        #
        # self.secrets = {
        #   "app": {
        #       "opensearch:app:admin-password": {
        #           "meta": <Secret instance>,
        #           "content": {
        #               "opensearch:app:admin-password": "bla"
        #           }
        #       }
        #   },
        #   "unit": {
        #       "opensearch:unit:0:certificates": {
        #           "meta": <Secret instance>,
        #           "content": {
        #               "ca-cert": "<certificate>",
        #               "cert": "<certificate>",
        #               "chain": "<certificate>"
        #           }
        #       }
        #   }
        # }
        self.secrets = {Scope.APP: {}, Scope.UNIT: {}}

    def get_meta(self, scope: Scope, label: str) -> Optional[Secret]:
        """Getting cached secret meta-information."""
        return self.secrets[scope].get(label, {}).get(self.CACHED_META)

    def set_meta(self, scope: Scope, label: str, secret: Secret) -> None:
        """Setting cached secret meta-information."""
        self.secrets[scope].setdefault(label, {}).update({self.CACHED_META: secret})

    def get_content(self, scope: Scope, label: str) -> Dict[str, str]:
        """Getting cached secret content."""
        return self.secrets[scope].get(label, {}).get(self.CACHED_CONTENT)

    def put_content(self, scope: Scope, label: str, content: Union[str, Dict[str, str]]):
        """Setting cached secret content."""
        self.secrets[scope].setdefault(label, {}).update({self.CACHED_CONTENT: content})

    def put(
        self,
        scope: Scope,
        label: str,
        secret: Optional[Secret] = None,
        content: Optional[Union[str, Dict[str, str]]] = None,
    ) -> None:
        """Updating cached secret information."""
        if secret:
            self.set_meta(scope, label, secret)
        if content:
            self.put_content(scope, label, content)

    def delete(self, scope: Scope, label: str) -> None:
        """Removing cached secret information."""
        self.secrets[scope].pop(label, None)
