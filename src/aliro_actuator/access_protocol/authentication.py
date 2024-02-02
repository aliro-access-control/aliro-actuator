from binascii import hexlify

from aliro_actuator import Global
from aliro_actuator.access_protocol.defines import EndpointAuth, ReaderAuth
from aliro_actuator.access_protocol.tlv import TLV
from aliro_actuator.trust_framework.key import PublicKey


def create_reader_authentication(
    reader_identifier: bytes,
    credential_epubk: PublicKey,
    reader_epubk: PublicKey,
    transaction_identifier: bytes,
) -> TLV:
    # create data fields
    data_fields: list[tuple[int, bytes | list]] = []
    data_fields.append((ReaderAuth.READER_IDENTIFIER_TAG, reader_identifier))
    data_fields.append(
        (ReaderAuth.CREDENTIAL_EPUBK_TAG, credential_epubk.get_x().to_bytes(32, "big"))
    )
    data_fields.append(
        (ReaderAuth.READER_EPUBK_TAG, reader_epubk.get_x().to_bytes(32, "big"))
    )
    data_fields.append((ReaderAuth.TRANSACTION_IDENTIFIER_TAG, transaction_identifier))
    data_fields.append((ReaderAuth.USAGE_TAG, ReaderAuth.USAGE))

    data = TLV(data_fields)
    Global.logger.debug(
        "reader authentication data: {!r}".format(hexlify(data.to_bytes()))
    )

    return data


def create_endpoint_authentication(
    reader_identifier: bytes,
    credential_epubk: PublicKey,
    reader_epubk: PublicKey,
    transaction_identifier: bytes,
) -> TLV:
    # create data fields
    data_fields: list[tuple[int, bytes | list]] = []
    data_fields.append((EndpointAuth.READER_IDENTIFIER_TAG, reader_identifier))
    data_fields.append(
        (
            EndpointAuth.CREDENTIAL_EPUBK_TAG,
            credential_epubk.get_x().to_bytes(32, "big"),
        )
    )
    data_fields.append(
        (EndpointAuth.READER_EPUBK_TAG, reader_epubk.get_x().to_bytes(32, "big"))
    )
    data_fields.append(
        (EndpointAuth.TRANSACTION_IDENTIFIER_TAG, transaction_identifier)
    )
    data_fields.append((EndpointAuth.USAGE_TAG, EndpointAuth.USAGE))

    data = TLV(data_fields)
    Global.logger.debug(
        "endpoint authentication data: {!r}".format(hexlify(data.to_bytes()))
    )

    return data
