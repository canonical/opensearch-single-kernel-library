#!/usr/bin/env python3
# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""A set of utility functions for managing peer clusters."""

from opensearch_single_kernel.core.base_models import (
    PeerClusterApp,
    PeerClusterOrchestrators,
    stripped_or_none,
)
from opensearch_single_kernel.core.relation_models import PeerClusterAppModel
from opensearch_single_kernel.core.relations import OpenSearchApplication, PeerClusterApplication
from opensearch_single_kernel.core.storage import AzureRelData, GcsRelData, S3RelData


def peer_cluster_credentials(
    source: OpenSearchApplication | PeerClusterApplication | PeerClusterAppModel,
) -> dict[str, str | None]:
    """Return the credentials shared over the peer-cluster relation, read from ``source``.

    Fields that may hold a " " placeholder (see initialize_empty_secrets) are collapsed
    to None when empty or whitespace-only.
    """
    return {
        # User secrets
        "admin_password": stripped_or_none(source.admin_password),
        "admin_hashed_password": source.admin_hashed_password,
        "kibana_server_password": source.kibana_server_password,
        "kibana_server_hashed_password": source.kibana_server_hashed_password,
        "monitor_password": source.monitor_password,
        "monitor_hashed_password": source.monitor_hashed_password,
        # Admin TLS secrets
        "admin_truststore_password": stripped_or_none(source.admin_truststore_password),
        "admin_keystore_password": stripped_or_none(source.admin_keystore_password),
        "admin_subject": stripped_or_none(source.admin_subject),
        "admin_key": stripped_or_none(source.admin_key),
        "admin_key_password": stripped_or_none(source.admin_key_password),
        "admin_csr": stripped_or_none(source.admin_csr),
        "admin_chain": stripped_or_none(source.admin_chain),
        "admin_cert": stripped_or_none(source.admin_cert),
        "admin_ca_cert": stripped_or_none(source.admin_ca_cert),
    }


def s3_backup_secrets(reldata: S3RelData | None) -> dict[str, str | None]:
    """Return the S3 backup secret fields (``None`` reldata clears them)."""
    return {
        "s3_access_key": reldata.access_key if reldata else None,
        "s3_secret_key": reldata.secret_key if reldata else None,
        "s3_tls_ca_chain": reldata.tls_ca_chain if reldata else None,
    }


def azure_backup_secrets(reldata: AzureRelData | None) -> dict[str, str | None]:
    """Return the Azure backup secret fields (``None`` reldata clears them)."""
    return {
        "azure_storage_account": reldata.storage_account if reldata else None,
        "azure_secret_key": reldata.secret_key if reldata else None,
    }


def gcs_backup_secrets(reldata: GcsRelData | None) -> dict[str, str | None]:
    """Return the GCS backup secret fields (``None`` reldata clears them)."""
    return {
        "gcs_secret_key": reldata.secret_key if reldata else None,
    }


def peer_cluster_secret_fields() -> list[str]:
    """Return the names of all secret-backed fields of the peer cluster app model."""
    return [name for name, field in PeerClusterAppModel.model_fields.items() if field.exclude]


def update_cluster_fleet(
    fleet_dict: dict[str | int, PeerClusterApp],
    app: PeerClusterApp,
    key: str | int | None = None,
) -> None:
    """Update fleet dictionary with the app, or remove the entry if no planned units."""
    if key is None:
        key = app.app.id

    if app.planned_units == 0:
        fleet_dict.pop(key, None)
        return

    fleet_dict.update({key: app})


def is_failover_promoted(orchestrators: PeerClusterOrchestrators) -> bool:
    """Checks if failover orchestrator was promoted to the main orchestrator"""
    return (
        orchestrators.failover_app is not None
        and orchestrators.main_app is not None
        and orchestrators.failover_app.id == orchestrators.main_app.id
    )
