"""AWS's typed KMS client satisfies the `KmsClient` protocol without a cast.

This file is checked by pyright (`make lint`), never run. boto3's stubs declare `SigningAlgorithm` and
`MessageType` as unions of literals; a protocol that accepted any `str` for them was one that client could
not satisfy, and mypy does not report that mismatch.
"""

from mypy_boto3_kms import KMSClient

from auditable_mcp.l2.adapters.aws_kms import AwsKmsCountersigner, AwsKmsSigner, KmsClient, load_kms_public_key


def boto3_client_is_a_kms_client(client: KMSClient) -> KmsClient:
    """Return the typed boto3 client as the protocol this adapter takes."""
    return client
    # end def


async def boto3_client_reaches_every_entry(client: KMSClient) -> None:
    """Hand the typed boto3 client to each entry that takes a `KmsClient`."""
    await load_kms_public_key(client, 'alias/example')
    await AwsKmsSigner.from_kms(client, 'alias/example')
    await AwsKmsCountersigner.from_kms(client, 'alias/example')
    # end def
