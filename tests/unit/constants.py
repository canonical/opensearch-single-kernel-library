#!/usr/bin/env python3
# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Constants used across the unit tests."""


_S3_PEM = """-----BEGIN CERTIFICATE-----
MIIDdTCCAl2gAwIBAgIUTestFakeCertForUnitTestsOnly1234567890
-----END CERTIFICATE-----"""

S3_CONN_INFO_WITH_CA = {
    "access-key": "ACCESS",
    "secret-key": "secret",
    "bucket": "mybucket",
    "endpoint": "https://s3.example.com",
    "region": "us-east-1",
    "path": "base/path",
    "tls_ca_chain": _S3_PEM,
}


DEFAULT_S3_INFO = {
    "access-key": "ACCESS",
    "secret-key": "secret",
    "bucket": "mybucket",
    "endpoint": "https://s3.example.com",
    "region": "us-east-1",
    "path": "base/path",
}

DEFAULT_AZURE_INFO = {
    "storage_account": "account",
    "secret_key": "key",
    "container": "backups",
    "endpoint": "https://acct.blob.core.windows.net",
    "path": "base/path",
}

DEFAULT_GCS_INFO = {
    "bucket": "my-gcs-bucket",
    "path": "base/path",
    "storage-class": "STANDARD",
    "secret_key": """{
        "type": "service_account",
        "project_id": "my-gcp-project",
        "private_key_id": "fakeprivatekeyid",
        "private_key": "-----BEGIN PRIVATE KEY-----\\nFAKEKEY\\n-----END PRIVATE KEY-----\\n",
        "client_email": "opensearch-backup@my-gcp-project.iam.gserviceaccount.com",
        "client_id": "123456789012345678901",
        "auth_uri": "https://accounts.google.com/o/oauth2/auth",
        "token_uri": "https://oauth2.googleapis.com/token",
        "auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
        "client_x509_cert_url": "https://www.googleapis.com/robot/v1/metadata/x509/opensearch-backup%40my-gcp-project.iam.gserviceaccount.com"
    }""",
}
