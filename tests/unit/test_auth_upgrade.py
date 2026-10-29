# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Preserve authentication configured by the stable operator across refresh."""

from types import SimpleNamespace
from unittest.mock import MagicMock, PropertyMock

import pytest
import yaml
from charmlibs.pathops import LocalPath
from pydantic import ValidationError

from opensearch_single_kernel.common.constants import (
    JWT_CONFIG_RELATION,
    OAUTH_RELATION,
    PEER_RELATION,
)
from opensearch_single_kernel.core.models import JWTAuthConfiguration
from opensearch_single_kernel.utils.config import YamlConfigSetter

JWT_CONFIG = {
    "signing_key": "synthetic-signing-key",
    "jwt_header": "Authorization",
    "jwt_url_parameter": None,
    "roles_key": "roles",
    "subject_key": "sub",
    "required_audience": "opensearch",
    "required_issuer": "test-issuer",
    "jwt_clock_skew_tolerance_seconds": 60,
}
OIDC_URL = "https://idp.example/.well-known/openid-configuration"


@pytest.fixture
def auth_upgrade(harness, mocker, tmp_path, substrate):
    """Use a real security YAML file and stop the upgrade flow at its rewrite."""
    if substrate != "vm":
        pytest.skip("The stable operator being migrated was a machine charm")
    manager = harness.charm.config_manager
    setter = YamlConfigSetter(harness.charm.workload)
    setter.base_path = LocalPath(str(tmp_path))
    path = tmp_path / manager.SECURITY_CONFIG_YML
    path.parent.mkdir(parents=True)
    mocker.patch.object(
        type(manager), "yaml_setter", new_callable=PropertyMock, return_value=setter
    )
    mocker.patch(
        "opensearch_single_kernel.managers.upgrades_base.YamlConfigSetter", return_value=setter
    )
    mocker.patch("opensearch_single_kernel.events.upgrades.get_charm_revision", return_value="1")
    mocker.patch.object(harness.charm.upgrades_manager, "update_grafana_dashboards_title")
    mocker.patch.object(
        harness.charm.cluster_manager,
        "initialise_security_index",
        side_effect=AssertionError("Auth migration must not write the security index"),
    )
    mocker.patch.object(
        manager,
        "apply_security_config",
        side_effect=AssertionError("Auth migration must not write the security index"),
    )
    events = harness.charm.upgrade_events
    mocker.patch.object(events, "machine_upgrade", side_effect=manager.update_security_config)

    def seed(jwt=True, oidc=True, relations=True):
        # These are the fields written by the old set_jwt_auth/add_oidc_auth methods.
        authc = {
            "jwt_auth_domain": {
                "http_enabled": jwt,
                "transport_enabled": jwt,
                "http_authenticator": {"config": dict(JWT_CONFIG)},
            }
        }
        if oidc:
            authc["openid_auth_domain"] = {
                "http_enabled": True,
                "transport_enabled": True,
                "http_authenticator": {"config": {"openid_connect_url": OIDC_URL}},
            }
        path.write_text(yaml.safe_dump({"config": {"dynamic": {"authc": authc}}}))
        with harness.hooks_disabled():
            relation = harness.model.get_relation(PEER_RELATION)
            harness.update_relation_data(
                relation.id, harness.charm.app.name, {"security_index_initialised": "True"}
            )
        if relations:
            with harness.hooks_disabled():
                harness.add_relation(JWT_CONFIG_RELATION, "jwt-integrator")
                harness.add_relation(OAUTH_RELATION, "oauth-provider")

    return SimpleNamespace(
        seed=seed,
        run=lambda: events._on_upgrade_charm(MagicMock()),
        authc=lambda: setter.load(manager.SECURITY_CONFIG_YML)["config"]["dynamic"]["authc"],
        path=path,
    )


@pytest.mark.real_fs
@pytest.mark.parametrize("jwt,oidc", [(True, True), (True, False), (False, True), (False, False)])
def test_upgrade_preserves_legacy_auth(harness, auth_upgrade, jwt, oidc):
    """Preserve enabled and disabled auth through migration and the first rewrite."""
    auth_upgrade.seed(jwt, oidc)
    with harness.hooks_disabled():
        harness.set_leader(True)
        auth_upgrade.run()

    authc = auth_upgrade.authc()
    assert harness.charm.state.application.is_security_index_initialised is True
    assert harness.charm.cluster_manager.should_initialise_security_index() is False
    assert authc["jwt_auth_domain"]["http_enabled"] is jwt
    assert authc["jwt_auth_domain"]["transport_enabled"] is jwt
    if jwt:
        assert authc["jwt_auth_domain"]["http_authenticator"]["config"] == JWT_CONFIG
    assert ("openid_auth_domain" in authc) is oidc
    if oidc:
        assert (
            authc["openid_auth_domain"]["http_authenticator"]["config"]["openid_connect_url"]
            == OIDC_URL
        )


@pytest.mark.real_fs
def test_follower_imports_auth_before_machine_upgrade(harness, mocker, auth_upgrade):
    """Followers must also import legacy state before the machine upgrade starts."""
    auth_upgrade.seed()
    with harness.hooks_disabled():
        harness.set_leader(False)
    before = auth_upgrade.path.read_text()

    def check_state(*_):
        server = harness.charm.state.server
        assert server.jwt_auth_configuration.to_dict() == JWT_CONFIG
        assert server.oauth_openid_connect_url == OIDC_URL

    mocker.patch.object(harness.charm.upgrade_events, "machine_upgrade", side_effect=check_state)
    auth_upgrade.run()
    assert auth_upgrade.path.read_text() == before


@pytest.mark.skip_if_substrate("vm")
def test_k8s_upgrade_does_not_migrate_legacy_machine_auth(harness, mocker):
    """K8s already uses peer auth state and has no old-stable YAML to migrate."""
    with harness.hooks_disabled():
        harness.add_relation(JWT_CONFIG_RELATION, "jwt-integrator")
        harness.add_relation(OAUTH_RELATION, "oauth-provider")
    mocker.patch("opensearch_single_kernel.events.upgrades.get_charm_revision", return_value="1")
    mocker.patch.object(harness.charm.upgrades_manager, "update_grafana_dashboards_title")
    upgrade = mocker.patch.object(harness.charm.upgrade_events, "kubernetes_upgrade")
    migrate = mocker.patch.object(
        harness.charm.upgrades_manager,
        "migrate_legacy_auth_configuration",
        side_effect=AssertionError("K8s must not read old machine auth configuration"),
    )

    harness.charm.upgrade_events._on_upgrade_charm(MagicMock())

    migrate.assert_not_called()
    upgrade.assert_called_once()


@pytest.mark.real_fs
def test_upgrade_preserves_newer_auth_state(harness, auth_upgrade):
    """Existing new-charm state takes precedence over the older file."""
    auth_upgrade.seed()
    new_jwt = JWTAuthConfiguration(signing_key="new-key", roles_key="new-roles")
    server = harness.charm.state.server
    server.jwt_auth_configuration = new_jwt
    server.oauth_openid_connect_url = "https://new.example/discovery"
    auth_upgrade.run()
    first = auth_upgrade.path.read_text()
    auth_upgrade.run()
    assert auth_upgrade.path.read_text() == first
    assert (
        auth_upgrade.authc()["jwt_auth_domain"]["http_authenticator"]["config"]
        == new_jwt.to_dict()
    )
    assert server.oauth_openid_connect_url == "https://new.example/discovery"


@pytest.mark.real_fs
def test_invalid_legacy_auth_stops_upgrade_before_rewrite(auth_upgrade):
    """Never replace enabled legacy auth with defaults when migration fails."""
    auth_upgrade.seed()
    document = yaml.safe_load(auth_upgrade.path.read_text())
    del document["config"]["dynamic"]["authc"]["jwt_auth_domain"]["http_authenticator"]["config"][
        "signing_key"
    ]
    auth_upgrade.path.write_text(yaml.safe_dump(document))
    before = auth_upgrade.path.read_text()
    with pytest.raises(ValidationError):
        auth_upgrade.run()
    assert auth_upgrade.path.read_text() == before


@pytest.mark.real_fs
def test_missing_legacy_file_stops_upgrade(auth_upgrade):
    """A missing file is not evidence that existing authentication is disabled."""
    auth_upgrade.seed()
    auth_upgrade.path.unlink()
    with pytest.raises(FileNotFoundError):
        auth_upgrade.run()
    assert not auth_upgrade.path.exists()


@pytest.mark.real_fs
def test_upgrade_without_auth_relations_does_not_import_stale_file(harness, auth_upgrade):
    """An old auth block alone must not re-enable an integration that was removed."""
    auth_upgrade.seed(relations=False)
    auth_upgrade.run()
    assert harness.charm.state.server.jwt_auth_configuration is None
    assert harness.charm.state.server.oauth_openid_connect_url is None
    assert auth_upgrade.authc()["jwt_auth_domain"]["http_enabled"] is False
    assert "openid_auth_domain" not in auth_upgrade.authc()
