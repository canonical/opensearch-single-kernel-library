# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Directory provisioning for the Authentik flavor of the LDAP integration test.

Authentik has no equivalent of the GLAuth `apply-ldif` action: its directory lives in the
Authentik server's database and is written through the REST API, authenticated with the API
token the Authentik server charm stores in a Juju secret.
"""

import logging

import requests
from tenacity import Retrying, retry_if_exception_type, stop_after_delay, wait_fixed

logger = logging.getLogger(__name__)

API_PORT = 9000
API_TOKEN_SECRET_LABEL = "authentik-api-token"


class AuthentikDirectory:
    """An Authentik REST API client scoped to what the LDAP integration test needs."""

    def __init__(self, host: str, token: str):
        self._base_url = f"http://{host}:{API_PORT}/api/v3"
        self._session = requests.Session()
        self._session.headers.update(
            {"Authorization": f"Bearer {token}", "Accept": "application/json"}
        )

    def wait_until_ready(self, timeout: int = 300) -> None:
        """Block until the Authentik API answers queries."""
        for attempt in Retrying(
            stop=stop_after_delay(timeout),
            wait=wait_fixed(5),
            retry=retry_if_exception_type(requests.RequestException),
            reraise=True,
        ):
            with attempt:
                self._request("GET", "/core/users/", params={"page_size": 1})

    def ensure_group(self, name: str) -> str:
        """Create the group if it does not exist yet and return its primary key."""
        for group in self._request("GET", "/core/groups/", params={"name": name})["results"]:
            if group["name"] == name:
                return group["pk"]

        logger.info("Creating Authentik group %s", name)
        return self._request("POST", "/core/groups/", json={"name": name})["pk"]

    def ensure_user(self, username: str, password: str, groups: list[str]) -> None:
        """Create or update a user with the given group membership and set its password."""
        payload = {
            "username": username,
            "name": username,
            "email": f"{username}@example.com",
            "is_active": True,
            "groups": groups,
        }
        existing = [
            user
            for user in self._request("GET", "/core/users/", params={"username": username})[
                "results"
            ]
            if user["username"] == username
        ]
        if existing:
            logger.info("Updating Authentik user %s", username)
            pk = existing[0]["pk"]
            self._request("PATCH", f"/core/users/{pk}/", json=payload)
        else:
            logger.info("Creating Authentik user %s", username)
            pk = self._request("POST", "/core/users/", json=payload | {"path": "users"})["pk"]

        # Passwords are never part of the user object; they are set through their own endpoint
        self._request("POST", f"/core/users/{pk}/set_password/", json={"password": password})

    def _request(self, method: str, path: str, **kwargs) -> dict:
        response = self._session.request(method, f"{self._base_url}{path}", timeout=30, **kwargs)
        response.raise_for_status()
        return response.json() if response.content else {}


def provision_directory(
    host: str, token: str, groups: list[str], users: dict[str, tuple[str, str]]
) -> None:
    """Create the groups and users in the Authentik directory.

    Args:
        host: address of the Authentik server.
        token: Authentik API token.
        groups: names of the groups to create.
        users: username -> (password, group name).
    """
    directory = AuthentikDirectory(host, token)
    directory.wait_until_ready()

    group_pks = {name: directory.ensure_group(name) for name in groups}
    for username, (password, group) in users.items():
        directory.ensure_user(username, password, [group_pks[group]])
