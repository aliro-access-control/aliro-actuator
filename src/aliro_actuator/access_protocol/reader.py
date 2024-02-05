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

import os
from binascii import hexlify

from aliro_actuator import READER_GROUP_ID_LENGTH, READER_GROUP_SUB_ID_LENGTH, Global
from aliro_actuator.access_protocol import Device
from aliro_actuator.access_protocol.apdu import (
    INS,
    Auth1Response,
    Response,
    StatusBytes,
    Transaction,
    TransactionCode,
)
from aliro_actuator.access_protocol.authentication import (
    create_reader_authentication,
    create_user_device_authentication,
)
from aliro_actuator.access_protocol.defines import (
    CSA_APPLICATION_TYPE,
    EXPEDITED_PHASE_AID,
    PROTOCOL_VERSION,
    Exchange,
    TransportProtocol,
)
from aliro_actuator.access_protocol.encryption import (
    DeviceType,
    EncryptionEngine,
    VerificationError,
    create_proprietary_information,
    create_salt,
)
from aliro_actuator.access_protocol.errors import (
    AccessProtocolError,
    InvalidResponseDataError,
    InvalidStatusError,
    SessionError,
    UnexpectedResponseError,
)
from aliro_actuator.access_protocol.tlv import TLV
from aliro_actuator.transport_protocol import Mode, TransportProtocolBase
from aliro_actuator.trust_framework.certificate import Certificate
from aliro_actuator.trust_framework.errors import InvalidKeyError
from aliro_actuator.trust_framework.key import KeyPair, PublicKey, derive_key
from aliro_actuator.trust_framework.reader_identifier import ReaderIdentifier


class Reader(Device):
    """
    Simulates a reader device.

    Args:
        transport_protocol (TransportProtocol): Transport protocol to use.
        transport_override (TransportProtocolBase | None, optional): Override the
        transport protocol. Mainly used for testing. Defaults to None.
        reader_group_identifier (bytes | None, optional): Part of the reader_identifier. Defaults to None.
        reader_group_sub_identifier (bytes | None, optional): Part of the reader_identifier. Defaults to None.
        reader_cert (bytes | None, optional): Reader certificate. Defaults to None.
        reader_key (KeyPair | None, optional): Reader Key. Defaults to None.

    Raises:
        AccessProtocolError: Raised when arguments have invalid format.
    """

    def __init__(
        self,
        transport_protocol: TransportProtocol,
        transport_override: TransportProtocolBase | None = None,
        reader_group_identifier: bytes | None = None,
        reader_group_sub_identifier: bytes | None = None,
        reader_cert: bytes | None = None,
        reader_key: KeyPair | None = None,
        vendor_extension: bytes | None = None,
    ):
        super().__init__(transport_protocol, transport_override)
        Global.logger.info(
            "Creating reader, using transport protocol: {}".format(
                TransportProtocol(transport_protocol).name
            )
        )

        if reader_key is None:
            self.reader_key = KeyPair()
        else:
            self.reader_key = reader_key
        Global.logger.info(
            "reader public key set to: {!r}".format(
                hexlify(self.reader_key.get_public_key_as_bytes())
            )
        )

        if reader_cert is not None:
            self.reader_cert: Certificate | None = Certificate.decode(reader_cert)
            Global.logger.info(
                "reader certificate set to: {!r}".format(hexlify(reader_cert))
            )
        else:
            self.reader_cert = None
            Global.logger.info("no reader certificate set")

        # generate identifiers if None is passed
        if reader_group_identifier is None:
            reader_group_identifier = os.urandom(READER_GROUP_ID_LENGTH)
        if reader_group_sub_identifier is None:
            reader_group_sub_identifier = os.urandom(READER_GROUP_SUB_ID_LENGTH)
        self.reader_identifier = reader_group_identifier + reader_group_sub_identifier
        Global.logger.info(
            "Reader group identifier set to: {!r}".format(
                hexlify(self.reader_group_identifier)
            )
        )
        Global.logger.info(
            "Reader group sub identifier set to: {!r}".format(
                hexlify(self.reader_group_sub_identifier)
            )
        )

        self.vendor_extension = vendor_extension

        self.session: ReaderSession | None = None
        Global.logger.info("Initialized Reader")

    @property
    def reader_identifier(self) -> bytes:
        return self._reader_identifier.as_bytes()

    @reader_identifier.setter
    def reader_identifier(self, reader_identifier: bytes) -> None:
        self._reader_identifier = ReaderIdentifier(reader_identifier)

    @property
    def reader_group_identifier(self) -> bytes:
        return self._reader_identifier.get_group()

    @property
    def reader_group_sub_identifier(self) -> bytes:
        return self._reader_identifier.get_group_sub()

    def transaction_initiation(self) -> None:
        """
        Initializes the hardware and sets up a connection to the card.
        """
        Global.logger.info("Start Transaction Initiation")
        self.transport_protocol.initialization(Mode.READER)
        self.transport_protocol.wait_for_connection()
        Global.logger.info("Transaction Initiation Done")

    def expedited_transaction_fast(self) -> None:
        raise NotImplementedError

    def expedited_transaction_standard(
        self, transaction_code: TransactionCode, load_cert: bool = False
    ) -> None:
        """
        Runs the Expedited Standard Phase.

        Args:
            transaction_code (TransactionCode): Passed during AUTH0.
            load_cert (bool, optional): Runs the load_cert command if True. Defaults to False.
        """
        if self.session is None:
            self.start_new_session()

        Global.logger.info("Start Expedited Transaction (standard)")
        self.handle_select(EXPEDITED_PHASE_AID)
        self.handle_auth0(Transaction.STANDARD, transaction_code)
        if load_cert:
            self.handle_load_cert()
        self.handle_auth1()
        Global.logger.info("Expedited Transaction (standard) Done")

    def step_up_transaction(self) -> None:
        raise NotImplementedError

    def start_new_session(
        self,
        transaction_identifier: bytes | None = None,
        ephemeral_key: KeyPair | None = None,
    ) -> None:
        """
        Start a new reader session. Must be done before using handle commands.
        This sessions stores all information received from commands.
        Start a new session to delete all received info and start over.

        Args:
            transaction_identifier (bytes | None, optional): Transaction identifier used
            for this session. Randomly generated if None. Defaults to None.
            ephemeral_key (KeyPair | None, optional): ephemeral reader key used for the
            session. Randomly generated if None. Defaults to None.
        """
        Global.logger.info("Starting new session")
        self.session = ReaderSession(
            self.reader_key, self.reader_identifier, self.vendor_extension
        )
        if transaction_identifier is None:
            self.session.transaction_identifier = os.urandom(16)
        else:
            self.session.transaction_identifier = transaction_identifier
        self.session.generate_ephemeral_key(ephemeral_key)

    def handle_select(self, aid: bytes) -> None:
        """
        create and send a select command.
        Required data from is retrieved from the Reader (self) and the session.
        The data contained in the response is stored in the session.

        Args:
            aid (bytes): AID to be send.

        Raises:
            SessionError: Raised if no session is found.
            AccessProtocolError: Raised if the response has invalid data.
            UnexpectedResponseError: Raised if the response has status/data that cannot be handled
        """
        if self.session is None:
            raise SessionError("No Session")

        Global.logger.info("SELECT Command")
        try:
            response = self.command_select(aid)
        except InvalidStatusError as error:
            if error.status == StatusBytes.FILE_OR_APP_NOT_FOUND:
                Global.logger.error("User does not recognize AID")
            raise error

        if response.compl_aid != EXPEDITED_PHASE_AID:
            raise AccessProtocolError("User send unknown AID")
        if response.type != CSA_APPLICATION_TYPE:
            raise AccessProtocolError("User send unknown application type")
        if PROTOCOL_VERSION not in response.expedited_phase_supported_protocol_versions:
            raise AccessProtocolError(
                "User does not support protocol version used by reader"
            )

        self.session.set_select_info(response)

    def handle_auth0(
        self, transaction_type: Transaction, transaction_code: TransactionCode
    ) -> None:
        """
        Create and send a AUTH0 command.
        Required data from is retrieved from the Reader (self) and the session.
        The data contained in the response is stored in the session.

        Args:
            transaction_type (Transaction): fast or standard
            transaction_code (TransactionCode): code with instruction (ex. Lock/Unlock)

        Raises:
            SessionError: Raised if no session is found.
            AccessProtocolError: Raised if the response has invalid data.
        """
        if self.session is None:
            raise SessionError("No Session")

        Global.logger.info("AUTH0 Command")
        auth0_response = self.command_auth0(
            transaction=transaction_type,
            transaction_code=transaction_code,
            protocol_version=PROTOCOL_VERSION,
            reader_epubk=self.session.get_reader_epubkey().as_bytes(),
            transaction_identifier=self.session.transaction_identifier,
            reader_identifier=self.reader_identifier,
            vendor_extension=self.vendor_extension,
        )

        if transaction_type == Transaction.STANDARD:
            Global.logger.info("checking Auth0 response fields")
            if auth0_response.cryptogram is not None:
                raise AccessProtocolError(
                    "User send cryptogram during a standard transaction"
                )
            try:
                credential_ephemeral_public_key = PublicKey(
                    auth0_response.credential_epubk
                )
            except InvalidKeyError as error:
                raise AccessProtocolError(
                    "invalid credential ephemeral public key received: {!r}".format(
                        hexlify(auth0_response.credential_epubk)
                    )
                ) from error

            Global.logger.info("saving Auth0 response data")
            self.session.set_flag(Transaction.STANDARD, transaction_code)
            self.session.set_credential_ephemeral_key(credential_ephemeral_public_key)
            self.session.set_response_vendor_extension(
                auth0_response.vendor_specific_extensions
            )

        elif transaction_type == Transaction.FAST:
            raise NotImplementedError

    def handle_load_cert(self) -> None:
        """
        Create and send a load_cert command.
        Required data from is retrieved from the Reader (self) and the session.
        The data contained in the response is stored in the session.


        Raises:
            SessionError: Raised if no session is found.
            AccessProtocolError: Raised if the response has invalid data.
        """
        if self.session is None:
            raise SessionError("No Session")

        Global.logger.info("LOAD CERT Command")
        if self.reader_cert is None:
            raise AccessProtocolError("No reader cert available")
        self.command_load_cert(self.reader_cert.encode_compressed())

    def handle_auth1(
        self,
        expected_response: Auth1Response = Auth1Response.CREDENTIAL_PUBLIC_KEY,
    ) -> None:
        """
        Create and send a AUTH1 command.
        Required data from is retrieved from the Reader (self) and the session.
        The data contained in the response is stored in the session.

        Raises:
            SessionError: Raised if no session is found.
        """
        if self.session is None:
            raise SessionError("No Session")

        Global.logger.info("Create shared keys")
        self.session.set_shared_key()
        self.session.derive_key_volatile(self.transport_protocol_type)

        Global.logger.info("AUTH1 Command")
        auth1_response = self.command_auth1(
            expected_response=expected_response,
            reader_identifier=self.reader_identifier,
            credential_epubk=self.session.credential_ephemeral_key,
            reader_epubk=self.session.get_reader_epubkey(),
            transaction_identifier=self.session.transaction_identifier,
            encryption=self.session.encryption,
        )

        Global.logger.info("Checking Auth1 response fields")
        if expected_response == Auth1Response.CREDENTIAL_PUBLIC_KEY:
            if auth1_response.credential_public_key is None:
                raise AccessProtocolError(
                    "Requested credential public key, but none was received"
                )
            credential_public_key = PublicKey(auth1_response.credential_public_key)
        elif expected_response == Auth1Response.KEY_SLOT:
            if auth1_response.key_slot is None:
                raise AccessProtocolError("Requested keyslot, but none was received")
            credential_public_key = self.session.lookup_credential_public_key(
                auth1_response.key_slot
            )

        Global.logger.info("Checking credential authentication data")
        self.session.set_credential_public_key(credential_public_key)
        if not self.session.check_user_device_authentication(
            auth1_response.user_device_signature
        ):
            raise AccessProtocolError("User device signature authentication failed")

        Global.logger.info("Save AUTH1 response")
        self.session.set_auth1_info(auth1_response)

    def handle_control_flow(self, success: bool) -> None:
        """
        Create and send a control_flow command.
        Required data from is retrieved from the Reader (self) and the session.
        The data contained in the response is stored in the session.

        Args:
            success (bool): if True, the command will indicate a success status.

        Raises:
            SessionError: Raised if no session is found.
        """
        if self.session is None:
            raise SessionError("No Session")

        Global.logger.info("CONTROL FLOW Command")

        if success:
            s1 = 0x01
        else:
            s1 = 0x00

        self.command_control_flow(s1, 0x00)

        self.session = None

    def handle_exchange(
        self,
        atomic_session: bool,
        read_requests: list[tuple[int, int]] | None,
        write_requests: list[tuple[int, bytes]] | None,
        set_requests: list[tuple[int, int, int]] | None,
        notify: TLV | None,
        ursk: bytes | None,
        update_doc: bytes | None,
    ) -> list[bytes]:
        """
        Create and send a exchange command.
        Required data from is retrieved from the Reader (self) and the session.
        The data contained in the response is stored in the session.

        Args:
            atomic_session (bool): if True, this is part of an atomic session
            read_requests (list[tuple[int, int]] | None): List of (offset, length) tuples.
            write_requests (list[tuple[int, bytes]] | None): list of (offset, data) tuples.
            set_requests (list[tuple[int, int, int]] | None): list of (offset, length, value) tuples.
            notify (TLV | None): Notify TLV
            ursk (bytes | None): URSK, for BLE
            update_doc (bytes | None): request update of an existing Access Document

        Raises:
            SessionError: Raised if no session is found.

        Returns:
            list[bytes]: list of read data.
        """
        if self.session is None:
            raise SessionError("No Session")

        Global.logger.info("EXCHANGE Command")

        payload: list[tuple[int, bytes | list]] = []
        if read_requests is not None:
            for read_request in read_requests:
                payload.append(
                    (
                        Exchange.READ_TAG,
                        read_request[0].to_bytes(2, "big")
                        + read_request[1].to_bytes(2, "big"),
                    )
                )
        if write_requests is not None:
            for write_request in write_requests:
                payload.append(
                    (
                        Exchange.WRITE_TAG,
                        write_request[0].to_bytes(2, "big") + write_request[1],
                    )
                )
        if set_requests is not None:
            for set_request in set_requests:
                payload.append(
                    (
                        Exchange.SET_TAG,
                        set_request[0].to_bytes(2, "big")
                        + set_request[1].to_bytes(2, "big")
                        + set_request[2].to_bytes(1, "big"),
                    )
                )
        if notify is not None:
            payload.append((Exchange.NOTIFY_TAG, notify.to_bytes()))
        if ursk is not None:
            payload.append((Exchange.URSK_TAG, ursk))
        if update_doc is not None:
            payload.append((Exchange.UPDATE_DOC_TAG, update_doc))

        payload_tlv = TLV(payload)

        response = self.command_exchange(
            atomic_session, payload_tlv, self.session.encryption
        )

        if response.status_code != bytes.fromhex("00020000"):
            Global.logger.error(
                "exchange returned error status: {!r}".format(response.status_code)
            )
            return []

        read_data = []

        index = 0
        while index < len(response.read_data):
            length = response.read_data[index]
            data = response.read_data[index + 1 : index + 1 + length]
            read_data.append(data)
            Global.logger.info("read data: {!r}".format(hexlify(data)))

        return read_data

    def command_auth0(
        self,
        transaction: Transaction,
        transaction_code: TransactionCode,
        protocol_version: int,
        reader_epubk: bytes,
        transaction_identifier: bytes,
        reader_identifier: bytes,
        vendor_extension: bytes | None = None,
    ) -> Response:
        """
        Create and send a auth0 command.

        Args:
            transaction (Transaction): fast or standard
            transaction_code (TransactionCode): code with instruction (ex. Lock/Unlock)
            protocol_version (int):
            reader_epubk (bytes): Reader Ephemeral Key as bytes
            transaction_identifier (bytes):
            reader_identifier (bytes):
            vendor_extension (bytes | None): Vendor specific extension TLV.
            Defaults to None.

        Returns:
            Response: Response containing the received data.
        """
        command = self.apdu.create_auth0_command(
            transaction,
            transaction_code,
            protocol_version,
            reader_epubk,
            transaction_identifier,
            reader_identifier,
            vendor_extension,
        )

        Global.logger.info("Sending AUTH0")
        self.transport_protocol.send_message(command.to_bytes())
        response_str = self.transport_protocol.get_message()
        response = self.apdu.parse_response(response_str, INS.AUTH0)
        Global.logger.info("Parsed AUTH0 Response")

        return response

    def command_auth1(
        self,
        expected_response: Auth1Response,
        reader_identifier: bytes,
        credential_epubk: PublicKey,
        reader_epubk: PublicKey,
        transaction_identifier: bytes,
        encryption: EncryptionEngine | None = None,
    ) -> Response:
        """
        Create and send a auth1 command.

        Args:
            expected_response (Auth1Response): key slot or credential public key
            reader_identifier (bytes):
            credential_epubk (PublicKey):
            reader_epubk (PublicKey):
            transaction_identifier (bytes):
            encryption (EncryptionEngine | None, optional): Encryption engine to decrypt the response.
            Response will not be decrypted if this is None. Defaults to None.

        Returns:
            Response: Response containing the received data.
        """
        data = create_reader_authentication(
            reader_identifier, credential_epubk, reader_epubk, transaction_identifier
        )
        reader_sig = self.reader_key.sign(data.to_bytes())
        Global.logger.debug(
            "reader authentication data signature: {!r}".format(hexlify(reader_sig))
        )

        command = self.apdu.create_auth1_command(expected_response, reader_sig)

        Global.logger.info("Sending AUTH1")
        self.transport_protocol.send_message(command.to_bytes())
        response_str = self.transport_protocol.get_message()
        response = self.apdu.parse_response(response_str, INS.AUTH1, encryption)
        Global.logger.info("Parsed AUTH1 Response")

        return response

    def command_select(self, aid: bytes) -> Response:
        """
        Create and send a select command.

        Args:
            aid (bytes): AID to be send.

        Returns:
            Response: Response containing the received data.
        """
        command = self.apdu.create_select_command(aid)

        Global.logger.info("Sending Select")
        Global.logger.debug("using AID: {!r}".format(hexlify(aid)))
        self.transport_protocol.send_message(command.to_bytes())
        response_str = self.transport_protocol.get_message()
        response = self.apdu.parse_response(response_str, INS.SELECT)
        Global.logger.info("Parsed Select Response")

        return response

    def command_envelope(self) -> None:
        raise NotImplementedError

    def command_get_response(self) -> None:
        raise NotImplementedError

    def command_load_cert(self, compressed_cert: bytes) -> Response:
        """
        Create and send a load_cert command.

        Args:
            compressed_cert (bytes): compressed certificate to send.

        Returns:
            Response: Response containing the received data.
        """
        command = self.apdu.create_load_cert_command(compressed_cert)

        Global.logger.info("Sending load cert")
        self.transport_protocol.send_message(command.to_bytes())
        response_str = self.transport_protocol.get_message()
        response = self.apdu.parse_response(response_str, INS.LOAD_CERT)
        Global.logger.info("Parsed load cert Response")

        return response

    def command_exchange(
        self, atomic_session: bool, payload: TLV, encryption: EncryptionEngine
    ) -> Response:
        """
        Create and send a exchange command.

        Args:
            atomic_session (bool): if True, this is part of an atomic session
            payload (TLV): The payload to send.
            encryption (EncryptionEngine): Encryption engine to encrypt the message and decode the response.

        Returns:
            Response: Response containing the received data.
        """
        command = self.apdu.create_exchange_command(atomic_session, payload, encryption)

        Global.logger.info("Sending exchange")
        self.transport_protocol.send_message(command.to_bytes())
        response_str = self.transport_protocol.get_message()
        response = self.apdu.parse_response(response_str, INS.EXCHANGE, encryption)
        Global.logger.info("Parsed exchange Response")

        return response

    def command_control_flow(
        self, s1: int, s2: int, domain_specific_data: bytes | None = None
    ) -> Response:
        """
        Create and send a exchange command.

        Args:
            s1 (int):
            s2 (int):
            domain_specific_data (bytes | None, optional): Defaults to None.

        Returns:
            Response: Response containing the received data.
        """
        command = self.apdu.create_control_flow_command(s1, s2, domain_specific_data)

        Global.logger.info("Sending control flow")
        self.transport_protocol.send_message(command.to_bytes())
        response_str = self.transport_protocol.get_message()
        response = self.apdu.parse_response(response_str, INS.CONTROL_FLOW)
        Global.logger.info("Parsed control flow Response")

        return response


class ReaderSession:
    """
    Contains info from a single session (with one User Device)
    """

    def __init__(
        self,
        reader_key: KeyPair,
        reader_identifier: bytes,
        vendor_extension: bytes | None = None,
    ) -> None:
        self.reader_key = reader_key
        self.reader_identifier = reader_identifier
        self.command_vendor_extension = vendor_extension
        self.response_vendor_extension: bytes | None = None

    @property
    def reader_identifier(self) -> bytes:
        return self._reader_identifier.as_bytes()

    @reader_identifier.setter
    def reader_identifier(self, reader_identifier: bytes) -> None:
        self._reader_identifier = ReaderIdentifier(reader_identifier)

    @property
    def reader_group_identifier(self) -> bytes:
        return self._reader_identifier.get_group()

    @property
    def reader_group_sub_identifier(self) -> bytes:
        return self._reader_identifier.get_group_sub()

    def set_select_info(self, select_response: Response) -> None:
        self.compl_aid = select_response.compl_aid
        self.application_type = select_response.type
        self.expedited_phase_supported_protocol_versions = (
            select_response.expedited_phase_supported_protocol_versions
        )
        self.maximum_command_apdu = select_response.maximum_command_apdu
        self.maximum_response_apdu = select_response.maximum_response_apdu
        self.proprietary_tlv = select_response.proprietary_tlv
        Global.logger.debug("Complete AID: {!r}".format(hexlify(self.compl_aid)))
        Global.logger.debug("application type: {}".format(self.application_type))
        Global.logger.debug(
            "Expedited Transaction Supported Versions: {!r}".format(
                self.expedited_phase_supported_protocol_versions
            )
        )

    @property
    def transaction_identifier(self) -> bytes:
        return self._transaction_identifier

    @transaction_identifier.setter
    def transaction_identifier(self, transaction_identifier: bytes) -> None:
        if not hasattr(self, "_transaction_identifier"):
            self._transaction_identifier = transaction_identifier
            Global.logger.debug(
                "set transaction identifier: {!r}".format(
                    hexlify(self._transaction_identifier)
                )
            )
        else:
            raise SessionError("Cannot set transaction identifier twice")

    def set_flag(
        self, transaction: Transaction, transaction_code: TransactionCode
    ) -> None:
        self.flag = bytes([transaction, transaction_code])

    def set_response_vendor_extension(self, vendor_extension: bytes | None) -> None:
        self.response_vendor_extension = vendor_extension

    def set_credential_ephemeral_key(self, key: PublicKey) -> None:
        self.credential_ephemeral_key = key
        Global.logger.debug(
            "set credential ephemeral key: {!r}".format(hexlify(key.as_bytes()))
        )

    def get_credential_ephemeral_key(self) -> bytes:
        return self.credential_ephemeral_key.as_bytes()

    def generate_ephemeral_key(self, ephemeral_key: KeyPair | None = None) -> None:
        if ephemeral_key is None:
            self.reader_ephemeral = KeyPair()
            Global.logger.info(
                "Generated reader ephemeral keypair, with public key: {!r}".format(
                    hexlify(self.reader_ephemeral.get_public_key_as_bytes())
                )
            )
        else:
            self.reader_ephemeral = ephemeral_key
            Global.logger.info("Generated reader ephemeral keypair")
            Global.logger.info(
                "Set reader ephemeral keypair, with public key: {!r}".format(
                    hexlify(self.reader_ephemeral.get_public_key_as_bytes())
                )
            )

    def get_reader_epubkey(self) -> PublicKey:
        return self.reader_ephemeral.get_public_key()

    def lookup_credential_public_key(self, key_slot: bytes) -> PublicKey:
        raise NotImplementedError

    def set_credential_public_key(self, key: PublicKey) -> None:
        self.credential_pubk = key

    def set_auth1_info(
        self,
        auth1_response: Response,
    ) -> None:
        self.private_mailbox_data = auth1_response.private_mailbox_data
        self.signaling_bitmap = auth1_response.signaling_bitmap
        self.credential_signed_timestamp = auth1_response.credential_signed_timestamp
        self.revocation_signed_timestamp = auth1_response.revocation_signed_timestamp
        self.access_credential_response = auth1_response.access_credential_response

    def check_user_device_authentication(self, user_device_signature: bytes) -> bool:
        data = create_user_device_authentication(
            self.reader_identifier,
            self.credential_ephemeral_key,
            self.reader_ephemeral.get_public_key(),
            self.transaction_identifier,
        )
        return self.credential_pubk.verify(data.to_bytes(), user_device_signature)

    def can_retrieve_access_credential(self) -> bool:
        return (self.signaling_bitmap[-1] & 0x01) == 0x01

    def can_retrieve_revocation_document(self) -> bool:
        return (self.signaling_bitmap[-1] & 0x02) == 0x02

    def step_up_aid_select_required(self) -> bool:
        return (self.signaling_bitmap[-1] & 0x04) == 0x04

    def set_shared_key(self) -> None:
        self.shared_key = self.reader_ephemeral.get_private_key().compute_shared_key(
            self.credential_ephemeral_key, self.transaction_identifier
        )

    def derive_key_volatile(self, transport_protocol: TransportProtocol) -> None:
        info = bytearray(self.credential_ephemeral_key.get_x().to_bytes(32, "big"))
        if self.command_vendor_extension is not None:
            info.extend(self.command_vendor_extension)
        if self.response_vendor_extension is not None:
            info.extend(self.response_vendor_extension)

        salt = create_salt(
            transport_protocol=transport_protocol,
            word=b"Volatile****",
            reader_public_key=self.reader_key.get_public_key(),
            reader_ephemeral_public_key=self.reader_ephemeral.get_public_key(),
            reader_identifier=self.reader_identifier,
            protocol_version=PROTOCOL_VERSION.to_bytes(2, "big"),
            transaction_identifier=self.transaction_identifier,
            flag=self.flag,
            proprietary_information=self.proprietary_tlv.to_bytes(),
        )
        derived_key = derive_key(self.shared_key, bytes(info), 160, salt)
        self.exchange_SK_reader = derived_key[0:32]
        self.exchange_SK_device = derived_key[32:64]
        self.step_up_SK = derived_key[64:96]
        self.ble_SK = derived_key[96:128]
        self.UR_SK = derived_key[128:160]

        self.encryption = EncryptionEngine(
            DeviceType.READER, self.exchange_SK_reader, self.exchange_SK_device
        )

    def encrypt_payload(self, payload: bytes) -> tuple[bytes, bytes]:
        return self.encryption.encrypt(payload)

    def decrypt_payload(
        self, encrypted_payload: bytes, authentication_tag: bytes
    ) -> bytes:
        return self.encryption.decrypt(encrypted_payload, authentication_tag)
