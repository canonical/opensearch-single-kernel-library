#!/usr/bin/env python3
# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Helpers for Cloud storage."""

import json
import logging
import os
import tempfile
import uuid

import boto3
from azure.core.exceptions import AzureError, ResourceExistsError, ResourceNotFoundError
from azure.storage.blob import ContainerClient
from botocore.client import Config
from botocore.exceptions import BotoCoreError, ClientError
from google.api_core.exceptions import Conflict, Forbidden, GoogleAPIError, NotFound
from google.cloud import storage
from pydantic import ValidationError

from opensearch_single_kernel.common.constants import (
    AZURE_REPOSITORY,
    GCS_REPOSITORY,
    S3_REPOSITORY,
    ObjectStorageType,
)
from opensearch_single_kernel.common.exceptions import (
    OpenSearchObjectStorageConfigValidationError,
)
from opensearch_single_kernel.core.models import (
    AzureRelData,
    GcsRelData,
    ObjectStorageConfig,
    S3RelData,
)

logger = logging.getLogger(__name__)


def repository_name(object_storage_type: ObjectStorageType) -> str | None:
    """Get the repository name for a given storage type.

    Args:
        object_storage_type: Object storage type

    Returns:
        repository name
    """
    if object_storage_type in {ObjectStorageType.S3, ObjectStorageType.S3_PCLUSTER}:
        return S3_REPOSITORY
    if object_storage_type in {ObjectStorageType.AZURE, ObjectStorageType.AZURE_PCLUSTER}:
        return AZURE_REPOSITORY
    if object_storage_type in {ObjectStorageType.GCS, ObjectStorageType.GCS_PCLUSTER}:
        return GCS_REPOSITORY
    raise ValueError(f"Unknown object storage type: {object_storage_type}")


def repository_type(object_storage_type: ObjectStorageType) -> str | None:
    """Return the repository type for a given object storage type.

    Args:
        object_storage_type (ObjectStorageType): The object storage type.

    Returns:
        repository_type
    """
    if object_storage_type in {ObjectStorageType.S3, ObjectStorageType.S3_PCLUSTER}:
        return "s3"
    if object_storage_type in {ObjectStorageType.AZURE, ObjectStorageType.AZURE_PCLUSTER}:
        return "azure"
    if object_storage_type in {ObjectStorageType.GCS, ObjectStorageType.GCS_PCLUSTER}:
        return "gcs"
    raise ValueError(f"Unknown object storage type: {object_storage_type}")


def get_s3_bucket_resource(s3_parameters: dict[str, str], verify: str | bool = True):
    """Build a boto3 S3 Bucket resource from connection parameters.

    Args:
        s3_parameters: Mapping containing S3 connection information.
        verify: TLS verification option passed to boto3.
            - True: verify using system CAs
            - False: disable TLS verification
            - str: path to a CA bundle file (file containing a custom CA)

    Returns:
        boto3.resources.factory.s3.Bucket: Bucket resource handle

    Raises:
        KeyError: If required keys are missing from s3_parameters.
        BotoCoreError: If boto3 fails to initialise the client/resource.
    """
    s3_resource = boto3.resource(
        "s3",
        region_name=s3_parameters.get("region"),
        endpoint_url=s3_parameters["endpoint"],
        aws_access_key_id=s3_parameters["access-key"],
        aws_secret_access_key=s3_parameters["secret-key"],
        config=Config(
            # https://github.com/boto/boto3/issues/4400#issuecomment-2600742103
            request_checksum_calculation="when_required",
            response_checksum_validation="when_required",
        ),
        verify=verify,
    )
    return s3_resource.Bucket(s3_parameters["bucket"])


def create_s3_bucket(s3_parameters: dict[str, str], verify: str | bool = True) -> None:
    """Create the configured S3 bucket.

    Args:
        s3_parameters: Mapping containing S3 connection information
                same as get_s3_bucket_resource().
        verify: TLS verification option passed to boto3.

    Raises:
        ClientError: If bucket creation fails for reasons other than already exists.
        BotoCoreError: If boto3 fails to initialise or make API calls.
    """
    region = s3_parameters.get("region")
    bucket = get_s3_bucket_resource(s3_parameters, verify=verify)
    is_aws_endpoint = "amazonaws.com" in (s3_parameters.get("endpoint", "").lower())

    try:
        # setting the `LocationConstraint` to the default value of us-east-1 will fail
        # https://github.com/aws/aws-sdk-js/issues/3647
        if is_aws_endpoint and region and region != "us-east-1":
            bucket.create(CreateBucketConfiguration={"LocationConstraint": region})
        else:
            bucket.create()
        bucket.wait_until_exists()

    except ClientError as e:
        msg = str(e)
        if (
            "BucketAlreadyOwnedByYou" in msg
            or "BucketAlreadyExists" in msg
            or "BucketNameUnavailable" in msg
        ):
            logger.info(f"Using existing bucket {s3_parameters['bucket']}")
            return

        logger.error(e, exc_info=True)
        raise

    logger.info(f"Bucket {s3_parameters['bucket']} is ready")


def verify_s3_credentials(storage_config: ObjectStorageConfig) -> bool:  # noqa: C901
    """Validate S3 credentials and CA using boto3.

    Args:
        storage_config: ObjectStorageConfig containing S3 settings (endpoint, bucket,
            region, base_path, credentials, and optional tls_ca_chain).

    Returns:
        True if credentials (and CA) work with S3, False otherwise.

    All errors are logged with the full traceback here.
    This function may create the bucket if it does not exist.
    """
    ca_tmp_path = None
    verify_param: str | bool = True

    # If we have a custom CA chain, write it to a temp file and pass it to boto3
    if storage_config.s3.tls_ca_chain:
        fd, ca_tmp_path = tempfile.mkstemp(prefix="opensearch-s3-ca-", suffix=".pem")
        with os.fdopen(fd, "w") as f:
            f.write(storage_config.s3.tls_ca_chain)
        verify_param = ca_tmp_path

    s3_params: dict[str, str] = {
        "access-key": storage_config.s3.access_key,
        "secret-key": storage_config.s3.secret_key,
        "bucket": storage_config.s3.bucket,
        "endpoint": storage_config.s3.endpoint,
        "region": storage_config.s3.region or "",
        "path": (storage_config.s3.path or "").strip("/"),
    }

    try:
        logger.info(
            "Verifying S3 with endpoint=%r bucket=%r region=%r has_ca=%r verify=%r",
            storage_config.s3.endpoint,
            storage_config.s3.bucket,
            storage_config.s3.region,
            bool(storage_config.s3.tls_ca_chain),
            verify_param,
        )

        bucket = get_s3_bucket_resource(s3_params, verify=verify_param)

        # check bucket exists + credentials/TLS are valid
        try:
            bucket.meta.client.head_bucket(Bucket=storage_config.s3.bucket)
        except ClientError as e:
            status_code = e.response.get("ResponseMetadata", {}).get("HTTPStatusCode")
            error_code = e.response.get("Error", {}).get("Code")
            bucket_missing = status_code == 404 or error_code in {"NoSuchBucket", "404"}

            if bucket_missing:
                logger.warning(
                    "S3 bucket %r not found; attempting to create it.", storage_config.s3.bucket
                )
                create_s3_bucket(s3_params, verify=verify_param)
            else:
                # auth/TLS/permission issue
                raise

        # write/delete to verify RW access
        prefix = s3_params["path"]
        probe_key = (
            f"{prefix}/.opensearch-verify-{uuid.uuid4().hex}"
            if prefix
            else f".opensearch-verify-{uuid.uuid4().hex}"
        )

        bucket.put_object(
            Key=probe_key,
            Body=b"opensearch-verify",
            ContentType="text/plain",
        )
        bucket.Object(probe_key).delete()

        logger.info("S3 credential validation with boto3 succeeded.")
        return True

    except (BotoCoreError, ClientError) as e:
        logger.error("S3 credential validation with boto3 failed: %s", e, exc_info=True)
        return False

    finally:
        if ca_tmp_path:
            try:
                os.remove(ca_tmp_path)
            except FileNotFoundError:
                pass


def get_azure_container_client(azure_parameters: dict[str, str]) -> ContainerClient:
    """Build an Azure Blob Storage ContainerClient from connection parameters.

    Args:
        azure_parameters: Mapping containing Azure connection information. Expected keys:
            - storage-account: Storage account name
            - container: Container name
            - secret-key: Account key (credential)
            - account-url: Optional account URL. If omitted,
                    defaults to a public Azure endpoint for the storage account.

    Returns:
        ContainerClient: Client bound to the target container.
    """
    if not (account_url := azure_parameters.get("account-url")):
        account_url = f"https://{azure_parameters['storage-account']}.blob.core.windows.net"

    return ContainerClient(
        account_url=account_url,
        container_name=azure_parameters["container"],
        credential=azure_parameters["secret-key"],
    )


def create_azure_container(azure_parameters: dict[str, str]) -> None:
    """Create the configured Azure blob container if it does not exist.

    Args:
        azure_parameters: Same mapping as get_azure_container_client().

    Raises:
        AzureError: The Azure SDK errors other than already exists.
    """
    container_client = get_azure_container_client(azure_parameters)
    try:
        container_client.create_container()
        logger.info(f"Container {azure_parameters['container']} created")
    except ResourceExistsError:
        logger.info(f"Container {azure_parameters['container']} already exists")
    except AzureError as e:
        logger.error(
            "Failed to create container %s: %s", azure_parameters["container"], e, exc_info=True
        )
        raise


def verify_azure_credentials(storage_config: ObjectStorageConfig) -> bool:
    """Validate Azure Blob Storage credentials using azure-storage-blob.

    Args:
        storage_config: ObjectStorageConfig containing Azure settings (endpoint,
            base_path, container, and credentials).

    Returns:
        True if credentials allow container access and write/delete operations,
        False otherwise.
    """
    if storage_config.azure.connection_protocol not in {"http", "https"}:
        logger.warning(
            "Azure Storage credential validation failed: unsupported connection protocol %s",
            storage_config.azure.connection_protocol,
        )
        return False

    try:
        account_name = storage_config.azure.storage_account
        account_key = storage_config.azure.secret_key
        container_name = storage_config.azure.container

        # Custom endpoint if present, else default public endpoint
        raw_endpoint = storage_config.azure.endpoint or ""
        if not (account_url := raw_endpoint.rsplit("/", 1)[0] if raw_endpoint else ""):
            account_url = f"https://{account_name}.blob.core.windows.net"

        azure_params: dict[str, str] = {
            "storage-account": account_name,
            "secret-key": account_key,
            "container": container_name,
            "account-url": account_url,
        }

        container_client = get_azure_container_client(azure_params)

        # ensure container exists and it also validates the credentials
        try:
            container_client.get_container_properties()
        except ResourceNotFoundError:
            logger.warning(
                "Azure container %r not found; attempting to create it.", container_name
            )
            create_azure_container(azure_params)
            container_client = get_azure_container_client(azure_params)

        # write/delete to validate RW access
        prefix = (storage_config.azure.path or "").strip("/")
        probe_name = (
            f"{prefix}/.opensearch-verify-{uuid.uuid4().hex}"
            if prefix
            else f".opensearch-verify-{uuid.uuid4().hex}"
        )

        blob_client = container_client.get_blob_client(probe_name)
        blob_client.upload_blob(b"opensearch-verify", overwrite=True)
        blob_client.delete_blob()

        logger.info("Azure Storage credential validation succeeded.")
        return True

    except AzureError as e:
        logger.error("Azure Storage credential validation failed: %s", e, exc_info=True)
        return False


def get_gcs_client(service_account_json: str) -> storage.Client:
    """Build a GCS client from a service-account JSON string.

    Args:
        service_account_json: JSON string for a service account key.

    Returns:
        google.cloud.storage.Client: Authenticated GCS client.

    Raises:
        ValueError: If the input is empty or not valid JSON.
        GoogleAPIError: If the client cannot be created due to SDK errors.
    """
    if not service_account_json:
        raise ValueError("Missing GCS secret_key (service account JSON).")

    try:
        service_account = json.loads(service_account_json)
    except (TypeError, ValueError) as e:
        raise ValueError("GCS secret_key is not valid JSON.") from e

    if "private_key" in service_account:
        service_account["private_key"] = service_account["private_key"].replace("\\n", "\n")

    client_kwargs: dict = {}
    if project_id := service_account.get("project_id"):
        client_kwargs["project"] = project_id

    return storage.Client.from_service_account_info(service_account, **client_kwargs)


def create_gcs_bucket(client: storage.Client, bucket: storage.Bucket) -> None:
    """Create a GCS bucket.

    Args:
        client: Authenticated google-cloud-storage client.
        bucket: Bucket handle to create.

    Raises:
        Conflict: If the bucket name is already taken (GCS bucket names are global).
        Forbidden: If the service account lacks storage.buckets.create permission.
        GoogleAPIError: For other GCS API errors.
    """
    try:
        client.create_bucket(bucket)
        logger.info("Created GCS bucket %r.", bucket.name)
    except Conflict:
        # GCS bucket names are global, and conflict means that name already taken
        logger.error(
            "GCS bucket %r could not be created because the name is already in use globally. "
            "Choose a unique bucket name (GCS bucket names are global).",
            bucket.name,
        )
        raise
    except Forbidden as e:
        logger.error(
            "Bucket %r cannot be created (forbidden). "
            "Service account likely missing storage.buckets.create. Error: %s",
            bucket.name,
            e,
            exc_info=True,
        )
        raise


def verify_gcs_credentials(object_storage_config: ObjectStorageConfig) -> bool:  # noqa: C901
    """Validate GCS credentials using google-cloud-storage.

    Args:
        object_storage_config: ObjectStorageConfig containing GCS
            settings (service-account JSON and bucket name).

    Returns:
        True if the service account can access the bucket (or create it if missing) and
        can write/delete an object in it; False otherwise.

    Behavior:
        - If the configured bucket does not exist, try to create it.
        - Verify access via write and delete a small dummy blob.
    """
    if not object_storage_config.gcs:
        logger.error("GCS credential validation failed: missing credentials block.")
        return False

    service_account_json = object_storage_config.gcs.secret_key
    bucket_name = object_storage_config.gcs.bucket

    if not service_account_json:
        logger.error("GCS credential validation failed: secret_key is empty.")
        return False
    if not bucket_name:
        logger.error("GCS credential validation failed: bucket name is missing.")
        return False

    try:
        client = get_gcs_client(service_account_json)
        bucket = client.bucket(bucket_name)

        # ensure bucket exists or create
        try:
            exists = bucket.exists()
        except Forbidden:
            # Some environments return 403 for exists() when the caller lacks storage.buckets.get.
            # In this case we best-effort try to create. But it may still fail
            # if bucket exists or permission is missing.
            logger.warning(
                "GCS bucket existence check returned 403 for %r; attempting to create it.",
                bucket_name,
            )
            exists = False

        if not exists:
            logger.warning("GCS bucket %r not found; attempting to create it.", bucket_name)
            try:
                create_gcs_bucket(client, bucket)
            except (Conflict, Forbidden):
                # this is already logged in the helper
                return False

        # write/delete to validate RW access
        prefix = (object_storage_config.gcs.path or "").strip("/")
        probe_name = (
            f"{prefix}/.opensearch-verify-{uuid.uuid4().hex}"
            if prefix
            else f".opensearch-verify-{uuid.uuid4().hex}"
        )

        blob = bucket.blob(probe_name)
        blob.upload_from_string(b"opensearch-verify", content_type="text/plain")
        blob.delete()

        logger.info("GCS credential validation succeeded.")
        return True

    except (ValueError, TypeError, KeyError) as e:
        logger.error("GCS credential validation failed: invalid credentials: %s", e, exc_info=True)
        return False

    except Forbidden as e:
        logger.error(
            "GCS credential validation failed: forbidden (missing permissions). Error: %s",
            e,
            exc_info=True,
        )
        return False

    except NotFound as e:
        logger.error(
            "GCS credential validation failed: not found (endpoint/resource mismatch). Error: %s",
            e,
            exc_info=True,
        )
        return False

    except GoogleAPIError as e:
        logger.error("GCS credential validation failed: %s", e, exc_info=True)
        return False


def storage_config_from_connection_info(
    object_storage_type: ObjectStorageType, connection_info: dict[str, str]
) -> ObjectStorageConfig | None:
    """Get the active object storage config from relations/peer-cluster.

    Args:
        object_storage_type (ObjectStorageType): the type of the object storage
        to get the config for.
        connection_info (dict[str, str]): the raw connection info to build the config from.

    Returns:
        ObjectStorageConfig | None: the active object storage config.
    """
    match object_storage_type:
        case ObjectStorageType.S3:
            data_model = S3RelData
        case ObjectStorageType.AZURE:
            data_model = AzureRelData
        case ObjectStorageType.GCS:
            data_model = GcsRelData
        case _:
            return
    try:
        rel_data = data_model.from_relation(connection_info) if connection_info else None
    except ValidationError as e:
        raise OpenSearchObjectStorageConfigValidationError(e) from e
    return ObjectStorageConfig(**{object_storage_type.value: rel_data}) if rel_data else None
