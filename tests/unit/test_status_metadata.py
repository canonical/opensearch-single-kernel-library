# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Guards for advanced StatusObject metadata (DA147 / DA161)."""

from enum import Enum

from opensearch_single_kernel.common import statuses as statuses_module


def _status_enums() -> list[type[Enum]]:
    return [
        value
        for name, value in vars(statuses_module).items()
        if isinstance(value, type) and issubclass(value, Enum) and value is not Enum
    ]


def test_long_messages_have_short_message():
    """short_message is required only when message is longer than 40 characters."""
    for enum_cls in _status_enums():
        for member in enum_cls:
            status = member.value
            if not status.message or len(status.message) <= 40:
                continue
            assert status.short_message, f"{enum_cls.__name__}.{member.name}: short_message"
            assert (
                len(status.short_message) <= 40
            ), f"{enum_cls.__name__}.{member.name}: short_message length"


def test_blocked_statuses_have_check_and_action():
    """Non-running blocked statuses expose check + action for operators."""
    for enum_cls in _status_enums():
        for member in enum_cls:
            status = member.value
            if status.status != "blocked" or not status.message or status.running is not None:
                continue
            assert status.check, f"{enum_cls.__name__}.{member.name}: check"
            assert status.action, f"{enum_cls.__name__}.{member.name}: action"


def test_format_status_preserves_metadata():
    from opensearch_single_kernel.common.statuses import NotificationsStatuses
    from opensearch_single_kernel.utils.status import format_status

    src = NotificationsStatuses.SMTP_NO_RELATION_DATA.value
    out = format_status(src, {"id": 7})
    assert "7" in out.message
    assert out.short_message == src.short_message
    assert out.check == src.check
    assert out.action == src.action
