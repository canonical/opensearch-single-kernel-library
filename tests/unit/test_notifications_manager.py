# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Unit tests for NotificationsManager pure status computation."""

from types import SimpleNamespace
from unittest.mock import MagicMock

from opensearch_single_kernel.common.constants import DeploymentType
from opensearch_single_kernel.common.statuses import (
    GeneralStatuses,
    NotificationsStatuses,
)
from opensearch_single_kernel.lib.charms.smtp_integrator.v0.smtp import (
    AuthType,
    SecretError,
    TransportSecurity,
)
from opensearch_single_kernel.managers.notification import NotificationsManager
from opensearch_single_kernel.utils.status import format_status


def _manager(*, deployment_type=DeploymentType.MAIN_ORCHESTRATOR, smtp_relations=None):
    state = MagicMock()
    state.application.deployment_description = SimpleNamespace(typ=deployment_type)
    state.smtp_relations = smtp_relations if smtp_relations is not None else []
    state.statuses.get.return_value = SimpleNamespace(root=[])
    workload = MagicMock()
    return NotificationsManager(state, workload), state


def _relation(rel_id: int = 42):
    rel = MagicMock()
    rel.id = rel_id
    return rel


def _smtp_data(
    *,
    host="127.0.0.1",
    port=2525,
    user="user",
    password="pass",
    auth_type=AuthType.PLAIN,
    transport_security=TransportSecurity.NONE,
    smtp_sender="no-reply@example.com",
    recipients=None,
):
    return SimpleNamespace(
        host=host,
        port=port,
        user=user,
        password=password,
        auth_type=auth_type,
        transport_security=transport_security,
        smtp_sender=smtp_sender,
        recipients=recipients or [],
    )


def test_get_statuses_active_when_no_smtp_relations():
    mgr, _ = _manager(smtp_relations=[])
    statuses = mgr.get_statuses("app")
    assert statuses == [GeneralStatuses.ACTIVE_IDLE.value]


def test_get_statuses_invalid_when_not_main_orchestrator():
    rel = _relation()
    mgr, _ = _manager(deployment_type=DeploymentType.OTHER, smtp_relations=[rel])

    statuses = mgr.get_statuses("app")

    assert NotificationsStatuses.SMTP_RELATION_INVALID.value in statuses


def test_relation_statuses_no_relation_data():
    mgr, state = _manager()
    rel = _relation(7)
    state.smtp_requires.get_relation_data_from_relation.return_value = None

    statuses = mgr._relation_statuses(rel)

    assert statuses == [
        format_status(NotificationsStatuses.SMTP_NO_RELATION_DATA.value, {"id": 7})
    ]


def test_relation_statuses_could_not_read_data():
    mgr, state = _manager()
    rel = _relation(9)
    state.smtp_requires.get_relation_data_from_relation.side_effect = SecretError(
        "Could not consume secret secret:123"
    )

    statuses = mgr._relation_statuses(rel)

    assert len(statuses) == 1
    assert statuses[0].status == "blocked"
    assert "Could not read smtp relation 9 data" in statuses[0].message
    assert "secret:123" in statuses[0].message


def test_relation_statuses_missing_required_parameters():
    mgr, state = _manager()
    rel = _relation(11)
    state.smtp_requires.get_relation_data_from_relation.return_value = _smtp_data(
        smtp_sender=None,
        password=None,
        user=None,
        auth_type=AuthType.PLAIN,
    )

    statuses = mgr._relation_statuses(rel)

    assert len(statuses) == 1
    assert statuses[0].status == "blocked"
    assert "parameters missing" in statuses[0].message
    assert "smtp_sender" in statuses[0].message


def test_relation_statuses_waiting_recipients():
    mgr, state = _manager()
    rel = _relation(13)
    state.smtp_requires.get_relation_data_from_relation.return_value = _smtp_data(recipients=[])

    statuses = mgr._relation_statuses(rel)

    assert statuses == [
        format_status(NotificationsStatuses.SMTP_WAITING_RECIPIENTS.value, {"id": 13})
    ]


def test_relation_statuses_ok_with_recipients_returns_empty():
    mgr, state = _manager()
    rel = _relation(15)
    state.smtp_requires.get_relation_data_from_relation.return_value = _smtp_data(
        recipients=["a@example.com"]
    )

    assert mgr._relation_statuses(rel) == []


def test_get_statuses_pure_no_put_side_effects(mocker):
    mgr, state = _manager()
    rel = _relation(17)
    state.smtp_relations = [rel]
    state.smtp_requires.get_relation_data_from_relation.return_value = _smtp_data(
        recipients=["a@example.com"]
    )
    put_sender = mocker.patch.object(mgr, "put_smtp_sender")
    put_group = mocker.patch.object(mgr, "put_email_group")
    put_channel = mocker.patch.object(mgr, "put_email_channel")

    statuses = mgr.get_statuses("app", recompute=True)

    put_sender.assert_not_called()
    put_group.assert_not_called()
    put_channel.assert_not_called()
    assert statuses == [GeneralStatuses.ACTIVE_IDLE.value]


def test_get_statuses_merges_cached_configuration_error():
    mgr, state = _manager()
    rel = _relation(19)
    state.smtp_relations = [rel]
    state.smtp_requires.get_relation_data_from_relation.return_value = _smtp_data(
        recipients=["a@example.com"]
    )
    cached_error = format_status(NotificationsStatuses.SMTP_CONFIGURATION_ERROR.value, {"id": 19})
    state.statuses.get.return_value = SimpleNamespace(root=[cached_error])

    statuses = mgr.get_statuses("app")

    assert cached_error in statuses


def test_get_statuses_missing_parameters_via_app_scope():
    mgr, state = _manager()
    rel = _relation(21)
    state.smtp_relations = [rel]
    state.smtp_requires.get_relation_data_from_relation.return_value = _smtp_data(smtp_sender=None)

    statuses = mgr.get_statuses("app")

    assert any("parameters missing" in s.message for s in statuses)
    assert any(s.status == "blocked" for s in statuses)
