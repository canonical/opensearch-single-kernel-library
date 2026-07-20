#!/usr/bin/env python3
# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

"""V1 Application charm that connects to opensearch using the opensearch-client relation."""

import json
import logging

import requests
from charms.data_platform_libs.v1.data_interfaces import (
    RequirerCommonModel,
    ResourceProviderModel,
    ResourceRequirerEventHandler,
)
from ops.charm import ActionEvent, CharmBase
from ops.main import main
from ops.model import ActiveStatus, BlockedStatus

logger = logging.getLogger(__name__)


CERT_PATH = "/tmp/test_cert.ca"


class V1ApplicationCharm(CharmBase):
    """V1 Application charm that connects to database charms.

    Enters BlockedStatus if it cannot constantly reach the database.
    """

    def __init__(self, *args):
        super().__init__(*args)
        # Default charm events.
        self.framework.observe(self.on.update_status, self._on_update_status)
        self.framework.observe(self.on.start, self._on_start)

        self.first_opensearch = ResourceRequirerEventHandler(
            self,
            "v1-first-index",
            [RequirerCommonModel(resource="albums_v1", extra_user_roles="")],
            ResourceProviderModel,
        )

        index_name = f'{self.app.name.replace("-", "_")}_second_opensearch'
        self.second_opensearch = ResourceRequirerEventHandler(
            self,
            "v1-second-index",
            [RequirerCommonModel(resource=index_name, extra_user_roles="hackerman")],
            ResourceProviderModel,
        )

        self.admin_opensearch = ResourceRequirerEventHandler(
            self,
            "v1-admin",
            [RequirerCommonModel(resource="admin-index", extra_user_roles="admin,default")],
            ResourceProviderModel,
        )

        self.relations = {
            "v1-first-index": self.first_opensearch,
            "v1-second-index": self.second_opensearch,
            "v1-admin": self.admin_opensearch,
        }

        for relation_handler in self.relations.values():
            self.framework.observe(
                relation_handler.on.resource_created, self._on_authentication_updated
            )
            self.framework.observe(
                relation_handler.on.authentication_updated, self._on_authentication_updated
            )

        self.framework.observe(self.on.run_request_action, self._on_run_request_action)

    def _on_start(self, _):
        """Check connection on start."""
        self.unit.status = BlockedStatus("Waiting for connection to opensearch charm")

    def _on_update_status(self, _) -> None:
        """Health check for index connection."""
        if self.connection_check():
            self.unit.status = ActiveStatus()
        else:
            logger.error("connection check to opensearch charm failed")
            self.unit.status = BlockedStatus("No connection to opensearch charm")

    def connection_check(self) -> bool:
        """Simple connection check to see if backend exists and we can connect to it."""
        relations = []
        for relation in self.relations.keys():
            relations += self.model.relations.get(relation, [])
        if not relations:
            return False

        connected = True
        for relation in relations:
            try:
                self.relation_request(relation.name, relation.id, "GET", "/")
            except Exception as e:
                logger.error(e)
                logger.error(f"relation {relation} didn't connect")
                connected = False

        return connected

    def _get_requires(self, relation_name):
        return self.relations.get(relation_name)

    def _on_authentication_updated(self, event):
        tls_ca = event.response.tls_ca
        if not tls_ca:
            event.defer()  # We're waiting until we get a CA.
            return

        logger.error(f"writing cert to {CERT_PATH}.")
        with open(CERT_PATH, "w") as f:
            f.write(tls_ca)

        self._on_update_status(None)

    def _on_run_request_action(self, event: ActionEvent):
        logger.info(event.params)
        relation_id = event.params["relation-id"]
        relation_name = event.params["relation-name"]
        method = event.params["method"]
        endpoint = event.params["endpoint"]
        payload = event.params.get("payload", None)
        if payload:
            payload = payload.replace("\\", "")

        relation = self.model.get_relation(relation_name, relation_id)
        requires = self._get_requires(relation_name)

        try:
            data_contract = requires.interface.build_model(relation.id, component=relation.app)
            responses = data_contract.requests
        except Exception as e:
            event.fail(f"Failed to build data contract: {e}")
            return

        if not responses:
            event.fail("Secrets not accessible yet.")
            return

        response = responses[0]

        if not response.username or not response.password or not response.endpoints:
            event.fail("Credentials or endpoints missing.")
            return

        host_addr, port = response.endpoints.split(",")[0].split(":")

        logger.info(f"sending {method} request to {endpoint}")
        try:
            req_response = self.request(
                method,
                endpoint,
                int(port),
                response.username,
                response.password,
                host_addr,
                payload,
            )
        except OpenSearchHttpError as e:
            req_response = [str(e)]

        event.set_results({"results": json.dumps(req_response)})

    def relation_request(
        self, relation_name: str, relation_id: int, method: str, endpoint: str, payload=None
    ):
        relation = self.model.get_relation(relation_name, relation_id)
        requires = self._get_requires(relation_name)

        data_contract = requires.interface.build_model(relation.id, component=relation.app)
        responses = data_contract.requests

        if not responses:
            raise OpenSearchHttpError("No connection data")

        response = responses[0]
        host, port = response.endpoints.split(",")[0].split(":")

        return self.request(
            method,
            endpoint,
            int(port),
            response.username,
            response.password,
            host,
            payload=payload,
        )

    def request(
        self,
        method: str,
        endpoint: str,
        port: int,
        username: str,
        password: str,
        host: str,
        payload=None,
    ):
        if None in [endpoint, method]:
            raise ValueError("endpoint or method missing")
        if endpoint.startswith("/"):
            endpoint = endpoint[1:]

        full_url = f"https://{host}:{port}/{endpoint}"

        request_kwargs = {
            "verify": CERT_PATH,
            "method": method.upper(),
            "url": full_url,
            "headers": {"Content-Type": "application/json", "Accept": "application/json"},
        }

        if isinstance(payload, str):
            request_kwargs["data"] = payload
        elif isinstance(payload, dict):
            request_kwargs["data"] = json.dumps(payload)

        try:
            with requests.Session() as s:
                s.auth = (username, password)
                resp = s.request(**request_kwargs)
                resp.raise_for_status()
        except requests.exceptions.RequestException as e:
            logger.error(f"Request {method} to {full_url} with payload: {payload} failed. \n{e}")
            raise OpenSearchHttpError(str(e))

        return resp.json()


class OpenSearchHttpError(Exception):
    pass


if __name__ == "__main__":
    main(V1ApplicationCharm)
