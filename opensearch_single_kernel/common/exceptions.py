#!/usr/bin/env python3
# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Charm-specific exceptions."""

import json
from typing import Optional

from pydantic import ValidationError


class OpenSearchError(Exception):
    """Base exception class for OpenSearch errors."""


class OpenSearchInstallError(OpenSearchError):
    """Exception thrown when OpenSearch fails to be installed."""


class OpenSearchMissingError(OpenSearchError):
    """Exception thrown when an action is attempted on OpenSearch when it's not installed."""


class OpenSearchStartError(OpenSearchError):
    """Exception thrown when OpenSearch fails to start."""


class OpenSearchStartTimeoutError(OpenSearchStartError):
    """Exception thrown when OpenSearch takes too long to start."""


class OpenSearchSecretError(OpenSearchError):
    """Parent exception for secrets related issues within OpenSearch."""


class OpenSearchSecretInsertionError(OpenSearchSecretError):
    """Exception thrown when a secret couldn't be updated / added."""


class OpenSearchHttpError(OpenSearchError):
    """Exception thrown when an OpenSearch REST call fails."""

    def __init__(self, response_text: Optional[str] = None, response_code: Optional[int] = None):
        self.response_text = response_text
        try:
            self.response_body = json.loads(response_text)
        except (json.JSONDecodeError, TypeError):
            self.response_body = {}
        self.response_code = response_code
        if self.response_body:
            message = f"HTTP error {self.response_code=}\n{self.response_body=}"
        else:
            message = f"HTTP error {self.response_code=}\n{self.response_text=}"
        super().__init__(message)


class OpenSearchHAError(OpenSearchError):
    """Exception thrown when the HA of the OpenSearch charm is violated."""


class OpenSearchNotFullyReadyError(OpenSearchError):
    """Exception thrown when a node is started but not full ready to take on requests."""


class OpenSearchUserMgmtError(OpenSearchError):
    """Base exception class for OpenSearch user management errors."""


class OpenSearchCmdError(OpenSearchError):
    """Exception thrown when an OpenSearch bin command fails."""

    def __init__(self, cmd: str, out: Optional[str] = None, err: Optional[str] = None):
        self.cmd = cmd
        self.out = out
        self.err = err
        super().__init__(f"Command failed: {cmd}\nstdout={out}\nstderr={err}")


class OpenSearchStopError(OpenSearchError):
    """Exception thrown when OpenSearch fails to stop."""


class OpenSearchProvidedRolesException(OpenSearchError):
    """Exception class for events when the user provided node roles will violate quorum."""


class OpenSearchExclusionsException(OpenSearchError):
    """Exception class for all Voting/Allocation exclusions related exceptions."""


class OpenSearchIndexError(OpenSearchError):
    """Exception thrown when an opensearch index is invalid."""


class OpenSearchFileOperationError(OpenSearchError):
    """Exception thrown when file operations related to OpenSearch fail."""


class OpenSearchObjectStorageConfigValidationError(OpenSearchError):
    """Raise when relation data is present but fails validation."""

    def __init__(self, error: ValidationError):
        super().__init__(str(error))
        self.error = error


class OpenSearchBackupRelationDataIncompleteError(OpenSearchError):
    """Exception thrown when the backup relation data is incomplete or invalid."""


class OpenSearchBackupCredentialsIncorrectError(OpenSearchError):
    """Exception thrown when the backup credentials provided are incorrect."""


class OpenSearchRestoreBackupError(OpenSearchError):
    """Exception thrown when restoring a backup fails."""


class OpenSearchPeerClusterRelationDataIncompleteError(OpenSearchError):
    """Exception thrown when the peer cluster relation data is incomplete or invalid."""


class OpenSearchSnapshotsPeerClusterDataConflictError(OpenSearchError):
    """Exception thrown when there is a conflict in the peer cluster relation data of snapshots."""


class OpenSearchPeerClusterDidntSaveCredentialsYetError(OpenSearchError):
    """Exception thrown when a cluster in the peer cluster relation didn't save the credentials."""


class OpenSearchInvalidStorageTypeError(OpenSearchError):
    """Exception thrown when an invalid storage type is provided for backup/restore operations."""


class OpenSearchSmtpMissingParametersError(OpenSearchError):
    """Exception thrown if there are missing parameters when generating smtp config."""

    def __init__(self, missing_parameters: list[str]) -> None:
        self.missing_parameters = missing_parameters
        super().__init__(
            f"Parameters missing from smtp-integrator: {', '.join(missing_parameters)}"
        )


class OpenSearchNoClusterManagersError(OpenSearchError):
    """Exception thrown when there are no cluster managers in the cluster."""

    def __init__(self):
        message = "No cluster managers left in the cluster fleet. Please scale up your cluster manager units."
        super().__init__(message)


class OpenSearchLockError(OpenSearchError):
    """Base exception for lock manager errors."""


class OpenSearchUpgradePrecheckError(OpenSearchError):
    """App is not ready to upgrade"""


class OpenSearchK8sDeployedWithoutTrustError(OpenSearchError):
    """Exception thrown when the charm is deployed on k8s without the --trust flag."""

    def __init__(self, *, app_name: str):
        self.app_name = app_name
        super().__init__(
            f"Run `juju trust {app_name} --scope=cluster` and `juju resolve` for each unit (or remove & re-deploy {app_name} with `--trust`)"
        )


class OpenSearchReconcilePartitionError(OpenSearchError):
    """Exception thrown when there is an error reconciling the partition during a k8s upgrade."""
