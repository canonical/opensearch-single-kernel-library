#!/usr/bin/env python3
# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Utilities for managing enums."""

from enum import Enum


class BaseStrEnum(str, Enum):
    """Base Enum class with str representation."""

    def __str__(self):
        """String representation of enum value."""
        return self.value

    @property
    def val(self) -> str:
        """String representation of enum values."""
        return str(self.__str__())
