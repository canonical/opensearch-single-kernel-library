#!/usr/bin/env python3
# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Constants used across the unit tests."""

_S3_PEM = """-----BEGIN CERTIFICATE-----
MIIDdTCCAl2gAwIBAgIUTestFakeCertForUnitTestsOnly1234567890
-----END CERTIFICATE-----"""

OLD_CA_PEM = """-----BEGIN CERTIFICATE-----
MIIBgzCCASmgAwIBAgIUKgp9WP9SwlthaH0vtzbRG63NhfIwCgYIKoZIzj0EAwIw
FjEUMBIGA1UEAwwLVGVzdCBPbGQgQ0EwIBcNMjYxMTE5MTEyNjUzWhgPMjEyNjEw
MjYxMTI2NTNaMBYxFDASBgNVBAMMC1Rlc3QgT2xkIENBMFkwEwYHKoZIzj0CAQYI
KoZIzj0DAQcDQgAEkE8HyLdNnkMYb6vsiD9911dHQW55jjMZR1o8L4zEycvB/uFV
05y07RDJpQzr3V2T8wq9lQYVSF7aYTx1DJsfhKNTMFEwHQYDVR0OBBYEFF9X7wuF
IWO76dnhBKBySjZCL6ihMB8GA1UdIwQYMBaAFF9X7wuFIWO76dnhBKBySjZCL6ih
MA8GA1UdEwEB/wQFMAMBAf8wCgYIKoZIzj0EAwIDSAAwRQIhAPMAEmAe6/bw6OJA
m5d3xpIJHdJrEOyVtFe7qzyfpYh4AiByQPjIFNKxY5W9bbxPVnea4Y3NRinsbghv
9sS/rxpqmw==
-----END CERTIFICATE-----
"""

NEW_CA_PEM = """-----BEGIN CERTIFICATE-----
MIIBgzCCASmgAwIBAgIUYT89ibFYlCEppmAVm3Y3x1LtxiYwCgYIKoZIzj0EAwIw
FjEUMBIGA1UEAwwLVGVzdCBOZXcgQ0EwIBcNMjYxMTE5MTEyNjUzWhgPMjEyNjEw
MjYxMTI2NTNaMBYxFDASBgNVBAMMC1Rlc3QgTmV3IENBMFkwEwYHKoZIzj0CAQYI
KoZIzj0DAQcDQgAE3GAxSatEPjbE+DJeJV43QdwrO9du3/cr9cI7KIJNzIYC7TdM
aqbURUhNzf5leOkEz3hKl30yeL2FW5pwEtvttKNTMFEwHQYDVR0OBBYEFKoaqi0T
7L0WOXuxUWRMJdGiAL8xMB8GA1UdIwQYMBaAFKoaqi0T7L0WOXuxUWRMJdGiAL8x
MA8GA1UdEwEB/wQFMAMBAf8wCgYIKoZIzj0EAwIDSAAwRQIhANoaMqF0s7e/oIgr
I6gV7S5Og9BUCIAivkgPfb4gFhkXAiB4+c15bxMZZQVhkTriq9DpBRYEaSTvVMKx
VtTpWE/PsQ==
-----END CERTIFICATE-----
"""

CHAIN_ROOT_CA_PEM = """-----BEGIN CERTIFICATE-----
MIIBoDCCAUegAwIBAgIUBM1RjJfIpa1ql8QeTYXodNT8uZYwCgYIKoZIzj0EAwIw
HTEbMBkGA1UEAwwSVGVzdCBDaGFpbiBSb290IENBMCAXDTI2MTEyMDA1MTAwOFoY
DzIxMjYxMDI3MDUxMDA4WjAdMRswGQYDVQQDDBJUZXN0IENoYWluIFJvb3QgQ0Ew
WTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAQFByKEFrc68QJxNfAJZNYeoz0f3Tb2
fc/JhJ8KH8qHEvukVQcgg8NS1o2zykqJGGl1Ip0HomFs3zlqJvdwcSfTo2MwYTAd
BgNVHQ4EFgQUOFPXDMqUjMBhamhyQlUDZa//VWAwHwYDVR0jBBgwFoAUOFPXDMqU
jMBhamhyQlUDZa//VWAwDwYDVR0TAQH/BAUwAwEB/zAOBgNVHQ8BAf8EBAMCAQYw
CgYIKoZIzj0EAwIDRwAwRAIgH5uZLt4gNSDncZo+SWRtAZrP/hNU7huzeJJSbDN3
aZICIFQD/jAQm0KtdN1zgD+UoGaXQqVXlAIzRPqHSpJ5m4Dv
-----END CERTIFICATE-----
"""

CHAIN_INTERMEDIATE_CA_PEM = """-----BEGIN CERTIFICATE-----
MIIBrDCCAVKgAwIBAgIUUcKJC6h235zlO+MDcUUW2/huh3owCgYIKoZIzj0EAwIw
HTEbMBkGA1UEAwwSVGVzdCBDaGFpbiBSb290IENBMCAXDTI2MTEyMDA1MTAwOFoY
DzIxMjYxMDI3MDUxMDA4WjAlMSMwIQYDVQQDDBpUZXN0IENoYWluIEludGVybWVk
aWF0ZSBDQTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABOZYjertDHrRUSpgdhSp
Pk70x8mmvZgVqtgHNNHrvVjkVqmZ6NZr/fGEIIWDMNs3fqr55IRrOcMyv6op7su+
k5KjZjBkMBIGA1UdEwEB/wQIMAYBAf8CAQAwDgYDVR0PAQH/BAQDAgEGMB0GA1Ud
DgQWBBQyQauS7+bWyqXhpcuha7do+EHplzAfBgNVHSMEGDAWgBQ4U9cMypSMwGFq
aHJCVQNlr/9VYDAKBggqhkjOPQQDAgNIADBFAiAgNSOGDT9s3JFt8sVwzIdqW6A2
wA7IndNtdPWVNz1siAIhALWMx9h7mFlGeYpKe3D2Q/SGIvykYJeJbAWqmR6Rz+j5
-----END CERTIFICATE-----
"""

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
    "storage-account": "account",
    "secret-key": "key",
    "connection-protocol": "https",
    "container": "backups",
    "endpoint": "https://acct.blob.core.windows.net",
    "path": "base/path",
}

DEFAULT_GCS_INFO = {
    "bucket": "my-gcs-bucket",
    "path": "base/path",
    "storage-class": "STANDARD",
    "secret-key": """{
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
