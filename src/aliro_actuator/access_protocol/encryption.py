# Copyright 2023 NXP
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from binascii import hexlify
from enum import Enum

from Crypto.Cipher import AES

from aliro_actuator import Global
from aliro_actuator.access_protocol.defines import Select, TransportProtocol
from aliro_actuator.access_protocol.errors import AccessProtocolError
from aliro_actuator.access_protocol.tlv import TLV
from aliro_actuator.trust_framework.key import PublicKey


class VerificationError(AccessProtocolError):
    """
    Raised when the verification of an AES decryption fails.
    """

    pass


class DeviceType(Enum):
    """
    Enumerator, used by the EncryptionEngine, to indicate if the device is a reader or user.
    """

    READER = 1
    USER = 2


class EncryptionEngine:
    """
    class to encrypt and decrypt messages. Uses AES-256.

    Args:
        devicetype (DeviceType): indicates if the device creating this class is a
        user or reader
        exchange_SK_reader (bytes): exchange SK Reader as described in Figure 8-13
        of the Aliro spec
        exchange_SK_device (bytes): exchange SK Device as described in Figure 8-13
        of the Aliro spec
    """

    def __init__(
        self,
        devicetype: DeviceType,
        exchange_SK_reader: bytes,
        exchange_SK_device: bytes,
    ):
        self.encryption_counter = 0x01
        self.decryption_counter = 0x01
        if devicetype == DeviceType.READER:
            self.encryption_key = exchange_SK_reader
            self.decryption_key = exchange_SK_device
            self.encryption_iv_pt1 = 0x00.to_bytes(8, "big")
            self.decryption_iv_pt1 = 0x01.to_bytes(8, "big")
        elif devicetype == DeviceType.USER:
            self.encryption_key = exchange_SK_device
            self.decryption_key = exchange_SK_reader
            self.encryption_iv_pt1 = 0x01.to_bytes(8, "big")
            self.decryption_iv_pt1 = 0x00.to_bytes(8, "big")

        Global.logger.debug("created encryption engine with:")
        Global.logger.debug("encryption key: {!r}".format(hexlify(self.encryption_key)))
        Global.logger.debug("decryption key: {!r}".format(hexlify(self.decryption_key)))

    def check_counters_valid(self) -> bool:
        """
        Checks the counters as required for the exchange command (Figure 8-15 of the Aliro spec)

        Returns:
            bool: True if the counters are valid (< 0xFFFF), else False
        """
        if self.encryption_counter >= 0xFFFF:
            return False
        if self.decryption_counter >= 0xFFFF:
            return False
        return True

    def encrypt(self, data: bytes, ad: bytes = b"") -> tuple[bytes, bytes]:
        """
        Generates encrypted data + authentication tag

        (figure 8-9 of the Aliro spec)

        Args:
            data (bytes): Data to encrypt. Can be any size.
            ad (bytes, optional): Additional data. Defaults to b"".

        Returns:
            tuple[bytes, bytes]: tuple of the encrypted data and the authentication tag.
        """
        iv = self.encryption_iv_pt1 + self.encryption_counter.to_bytes(4, "big")
        cipher = AES.new(self.encryption_key, AES.MODE_GCM, nonce=iv)
        cipher.update(ad)
        ciphertext, authentication_tag = cipher.encrypt_and_digest(data)
        self.encryption_counter += 1
        return ciphertext, authentication_tag

    def decrypt(
        self, ciphertext: bytes, authentication_tag: bytes, ad: bytes = b""
    ) -> bytes:
        """
        decrypts encrypted data and indicates if verification succeeded

        (figure 8-10 of the Aliro spec)

        Args:
            ciphertext (bytes): Ciphertext. Can be any size.
            authentication_tag (bytes): Authentication Tag. Must be 16 bytes.
            ad (bytes, optional): Additional data. Defaults to b"".

        Raises:
            VerificationError: raised when the verification fails.

        Returns:
            bytes: decrypted plaintext
        """
        iv = self.decryption_iv_pt1 + self.decryption_counter.to_bytes(4, "big")
        cipher = AES.new(self.decryption_key, AES.MODE_GCM, nonce=iv)
        cipher.update(ad)
        plaintext = cipher.decrypt(ciphertext)
        try:
            cipher.verify(authentication_tag)
        except ValueError:
            self.decryption_counter += 1
            raise VerificationError
        self.decryption_counter += 1

        return plaintext


def create_salt(
    transport_protocol: TransportProtocol,
    word: bytes,
    reader_public_key: PublicKey,
    reader_ephemeral_public_key: PublicKey,
    reader_identifier: bytes,
    protocol_version: bytes,
    transaction_identifier: bytes,
    flag: bytes,
    proprietary_information: bytes,
    credential_ephemeral_public_key: PublicKey | None = None,
) -> bytes:
    """
    Generates the salt used for key generation

    Args:
        transport_protocol (TransportProtocol): The transport protocol used.
        word (bytes): "VolatileFast", "Volatile****" or "Persistent**".
        reader_public_key (PublicKey).
        reader_ephemeral_public_key (PublicKey).
        reader_identifier (bytes).
        protocol_version (bytes).
        transaction_identifier (bytes).
        flag (bytes): command_parameters || transaction_code.
        proprietary_information (bytes): proprietary information.
        credential_ephemeral_public_key (PublicKey | None, optional): only for "VolatileFast" or "Persistent**". Defaults to None.

    Returns:
        bytes: the salt as bytes
    """
    if (
        transport_protocol == TransportProtocol.BLE_UWB
        or transport_protocol == TransportProtocol.SOCKET_BLE
    ):
        interface_byte = 0xC3
    elif (
        transport_protocol == TransportProtocol.NFC
        or transport_protocol == TransportProtocol.SOCKET_NFC
    ):
        interface_byte = 0x5E

    salt = bytearray()
    salt.extend(reader_public_key.get_x().to_bytes(32, "big"))
    salt.extend(word)
    salt.extend(reader_identifier)
    salt.append(interface_byte)
    salt.append(0x5C)
    salt.append(0x02)
    salt.extend(protocol_version)
    salt.extend(reader_ephemeral_public_key.get_x().to_bytes(32, "big"))
    salt.extend(transaction_identifier)
    salt.extend(flag)
    salt.extend(
        bytes([Select.PROPRIETARY_TAG, len(proprietary_information)])
        + proprietary_information
    )
    if credential_ephemeral_public_key is not None:
        salt.extend(credential_ephemeral_public_key.get_x().to_bytes(32, "big"))

    Global.logger.debug("created salt: {!r}".format(hexlify(salt)))
    return bytes(salt)


def create_proprietary_information(
    type: int,
    expedited_phase_supported_protocol_versions: list[int],
    maximum_command_apdu: int | None = None,
    maximum_response_apdu: int | None = None,
    vendor_specific_tlv: TLV | None = None,
) -> TLV:
    """
    Creates the proprietary information (see Table 10-2), used for salt generation and
    Select command.

    Args:
        type (int): Application type (see Table 10-3)
        expedited_phase_supported_protocol_versions (list[int]): List of supported
        protocol versions.
        maximum_command_apdu (int | None, optional): Defaults to None.
        maximum_response_apdu (int | None, optional): Defaults to None.
        vendor_specific_tlv (TLV | None, optional): Defaults to None.

    Returns:
        TLV: Proprietary information (as TLV)
    """
    etspv_bytes = bytearray()
    for value in expedited_phase_supported_protocol_versions:
        etspv_bytes.extend(value.to_bytes(2, "big"))
    etspv_bytes_imm = bytes(etspv_bytes)

    proprietary_tlv: list[tuple[int, bytes | list]] = [
        (Select.TYPE_TAG, type.to_bytes(2, "big")),
        (Select.ETSPV_TAG, etspv_bytes_imm),
    ]

    if maximum_command_apdu is not None and maximum_response_apdu is not None:
        extended_length_tlv: list[tuple[int, bytes | list]] = [
            (Select.MAX_COMMAND_TAG, maximum_command_apdu.to_bytes(2, "big")),
            (Select.MAX_RESPONSE_TAG, maximum_response_apdu.to_bytes(2, "big")),
        ]
        proprietary_tlv.append((Select.EXTENDED_INFO_TAG, extended_length_tlv))

    if vendor_specific_tlv is not None:
        proprietary_tlv.append(
            (Select.VENDOR_SPECIFIC_TAG, vendor_specific_tlv.to_data())
        )

    return TLV(proprietary_tlv)
