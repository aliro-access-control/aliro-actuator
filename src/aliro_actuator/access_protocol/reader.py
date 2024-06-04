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
from __future__ import annotations

import os
from binascii import hexlify

from aliro_actuator import READER_GROUP_ID_LENGTH, READER_GROUP_SUB_ID_LENGTH, Global
from aliro_actuator.access_protocol import Device
from aliro_actuator.access_protocol.apdu import (
    AUTHENTICATION_TAG_SIZE,
    INS,
    Auth1Response,
    Message,
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
    STEPUP_PHASE_AID,
    Auth1,
    Exchange,
    Select,
    TransportProtocol,
)
from aliro_actuator.access_protocol.encryption import (
    DeviceType,
    EncryptionEngine,
    VerificationError,
    create_salt,
    decrypt_cryptogram,
)
from aliro_actuator.access_protocol.errors import (
    AccessProtocolError,
    CryptogramNotFound,
    InvalidResponseError,
    InvalidStatusError,
    SessionError,
    UnexpectedNotificationDataError,
)
from aliro_actuator.access_protocol.tlv import TLV, TlvError
from aliro_actuator.transport_protocol import MessageType, Mode, TransportProtocolBase
from aliro_actuator.transport_protocol.ble_message_format import BleAttribute
from aliro_actuator.trust_framework.certificate import Certificate
from aliro_actuator.trust_framework.errors import InvalidKeyError
from aliro_actuator.trust_framework.key import KeyPair, PublicKey, derive_key
from aliro_actuator.trust_framework.reader_identifier import ReaderIdentifier


class ReaderStorage:
    """
    Cross-session storage for Expedited Fast cached data
    """

    def __init__(self) -> None:
        self.fast_cache: list[ReaderFastCacheEntry] = []
        self.fast_cache_size_limit = 16

    def add_kpersistent(
        self,
        access_credential: PublicKey,
        kpersistent: bytes,
    ) -> ReaderFastCacheEntry:
        data = ReaderFastCacheEntry(
            access_credential=access_credential,
            kpersistent=kpersistent,
        )

        # If an entry already exists for this access credential, remove it
        try:
            self.remove_kpersistent(access_credential)
        except ValueError:
            pass

        self.fast_cache.append(data)
        if len(self.fast_cache) > self.fast_cache_size_limit:
            self.fast_cache.pop(0)
        return data

    def get_kpersistent_list(self) -> list[ReaderFastCacheEntry]:
        return self.fast_cache

    def remove_kpersistent(self, access_credential: PublicKey) -> None:
        idx = list(
            map(lambda x: x.access_credential == access_credential, self.fast_cache)
        ).index(True)
        self.fast_cache.pop(idx)

    def clear_kpersistent(self) -> None:
        self.fast_cache = []


class Reader(Device):
    """
    Simulates a reader device.

    Args:
        transport_protocol (TransportProtocol): Transport protocol to use.
        transport_override (TransportProtocolBase | None, optional): Override the
        transport protocol. Mainly used for testing. Defaults to None.
        reader_group_identifier (bytes | None, optional): Part of the reader_identifier.
        Defaults to None.
        reader_group_sub_identifier (bytes | None, optional): Part of the
        reader_cert (bytes | None, optional): Reader certificate. Defaults to None.
        reader_key (KeyPair | None, optional): Reader Key. Defaults to None.
        vendor_extension (bytes | None, optional): Defaults to None.
        fast_transaction_implemented (bool): Indicates if this reader implements the
        fast transaction. Defaults to True.
        reader_storage (ReaderStorage | None, optional): Defaults to None.
        group_resolving_key (bytes, optional): Defaults to
        0x00000000000000000000000000000000.
        spsm (bytes, optional): Defaults to 0x0080.
        transaction_identifier_list (list[bytes] | None, optional): list of transaction
        identifiers to be used by the reader. first transaction uses index 0, second
        transaction uses index 1, etc. transaction identifiers are randomly generated if
        this is set to None. Defaults to None.
        ephemeral_key_list (list[KeyPair] | None, optional): list of ephemeral keys
        to be used by the reader. first transaction uses index 0, second
        transaction uses index 1, etc. Ephemeral keys are randomly generated if
        this is set to None. Defaults to None.

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
        fast_transaction_implemented: bool = True,
        reader_storage: ReaderStorage | None = None,
        group_resolving_key: bytes = 16 * bytes.fromhex("00"),
        spsm: bytes = bytes.fromhex("0080"),
        transaction_identifier_list: list[bytes] | None = None,
        ephemeral_key_list: list[KeyPair] | None = None,
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
        self.fast_transaction_implemented = fast_transaction_implemented

        self.session: ReaderSession | None = None

        if reader_storage is None:
            reader_storage = ReaderStorage()
        self.storage = reader_storage

        self.group_resolving_key = group_resolving_key
        self.spsm = spsm

        self.transaction_identifier_list = transaction_identifier_list
        self.ephemeral_key_list = ephemeral_key_list

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

    async def transaction_initiation(self) -> None:
        """
        Initializes the hardware and sets up a connection to the card.
        """
        Global.logger.info("Start Transaction Initiation")
        await self.setup_connection()

        self.start_new_session()
        if (
            self.transport_protocol_type == TransportProtocol.BLE_UWB
            or self.transport_protocol_type == TransportProtocol.SOCKET_BLE
        ):
            await self.wait_for_initiate_access_protocol_notification()
        else:
            await self.handle_select(EXPEDITED_PHASE_AID)
        Global.logger.info("Transaction Initiation Done")

    async def transaction_termination(self) -> None:
        """
        Terminates the connection to the user device.
        """
        Global.logger.info("Terminating transaction")
        self.end_session()
        await self.transport_protocol.disconnect()
        Global.logger.info("Transaction Termination Done")

    async def setup_connection(self) -> None:
        """
        Setup up the connection to the User device.
        """
        Global.logger.info("Setting up connection")
        await self.transport_protocol.initialization(
            Mode.READER,
            reader_group_identifier=self.reader_group_identifier,
            reader_group_sub_identifier=self.reader_group_sub_identifier,
            group_resolving_key=self.group_resolving_key,
            spsm=self.spsm,
        )
        await self.transport_protocol.wait_for_connection()
        Global.logger.info("Connection established")

    async def expedited_transaction_fast(
        self, transaction_code: TransactionCode
    ) -> None:
        Global.logger.info("Start Expedited Transaction (fast)")
        await self.handle_auth0(Transaction.FAST, transaction_code)
        Global.logger.info("Expedited Transaction (fast) Done")

    async def expedited_transaction_standard(
        self, transaction_code: TransactionCode, load_cert: bool = False
    ) -> None:
        """
        Runs the Expedited Standard Phase.

        Args:
            transaction_code (TransactionCode): Passed during AUTH0.
            load_cert (bool, optional): Runs the load_cert command if True.
            Defaults to False.
        """
        Global.logger.info("Start Expedited Transaction (standard)")
        await self.handle_auth0(Transaction.STANDARD, transaction_code)
        if load_cert:
            await self.handle_load_cert()
        await self.handle_auth1()
        Global.logger.info("Expedited Transaction (standard) Done")

    def step_up_transaction(self) -> None:
        raise NotImplementedError

    def start_new_session(
        self,
    ) -> None:
        """
        Start a new reader session. Must be done before using handle commands.
        This sessions stores all information received from commands.
        Start a new session to delete all received info and start over.
        """
        Global.logger.info("Starting new session")
        self.session = ReaderSession(
            self.reader_key, self.reader_identifier, self.vendor_extension
        )
        if (
            self.transaction_identifier_list is None
            or len(self.transaction_identifier_list) == 0
        ):
            self.session.transaction_identifier = os.urandom(16)
        else:
            self.session.transaction_identifier = self.transaction_identifier_list.pop(
                0
            )

        if self.ephemeral_key_list is None or len(self.ephemeral_key_list) == 0:
            self.session.generate_ephemeral_key()
        else:
            self.session.generate_ephemeral_key(self.ephemeral_key_list.pop(0))

    def end_session(self) -> None:
        """
        End the current reader session.
        """
        Global.logger.info("Ending session")
        self.session = None

    async def failure_process(self) -> None:
        """
        Should be called when a failure state has occurred.
        Destroys all session bound keys and data.
        If transport protocol is NFC, a control_flow command indicating failure is send.
        If transport protocol is BLE, a failure event message is send.
        """
        if (
            self.transport_protocol_type == TransportProtocol.NFC
            or self.transport_protocol_type == TransportProtocol.SOCKET_NFC
        ):
            await self.handle_control_flow(False)
        if (
            self.transport_protocol_type == TransportProtocol.BLE_UWB
            or self.transport_protocol_type == TransportProtocol.SOCKET_BLE
        ):
            # TODO: implement failure event message
            pass

        await self.transaction_termination()

    async def wait_for_initiate_access_protocol_notification(self) -> None:
        if self.session is None:
            raise SessionError("No Session")

        Global.logger.info("Waiting for Initiate access protocol notification")
        response_str = await self.transport_protocol.get_message(
            MessageType.INITIATE_ACCESS_PROTOCOL
        )
        attribute = BleAttribute.from_bytes(response_str)
        if attribute.id != 0x00:
            raise AccessProtocolError("User send unknown attribute ID")
        self.session.set_initiate_access_protocol_info(attribute.value)

        if self.session.application_type != CSA_APPLICATION_TYPE:
            raise AccessProtocolError("User send unknown application type")
        else:
            Global.logger.info(
                "Application type valid: 0x{:04x}".format(self.session.application_type)
            )

        if (
            PROTOCOL_VERSION
            not in self.session.expedited_phase_supported_protocol_versions
        ):
            raise AccessProtocolError(
                "User does not support protocol version used by reader"
            )
        else:
            Global.logger.info(
                "Protocol versions contains valid version: {}".format(
                    ", ".join(
                        str(hex(x))
                        for x in self.session.expedited_phase_supported_protocol_versions
                    )
                )
            )

        Global.logger.info("Initiate access protocol notification handling done")

    async def handle_select(self, aid: bytes) -> None:
        """
        create and send a select command.
        Required data from is retrieved from the Reader (self) and the session.
        The data contained in the response is stored in the session.

        Args:
            aid (bytes): AID to be send.

        Raises:
            SessionError: Raised if no session is found.
            AccessProtocolError: Raised if the response has invalid data.
            UnexpectedResponseError: Raised if the response has status/data that
            cannot be handled
        """
        if self.session is None:
            raise SessionError("No Session")

        Global.logger.info("Start handling SELECT with AID: {!r}".format(hexlify(aid)))
        try:
            response = await self.command_select(aid)
        except InvalidStatusError as error:
            if error.status == StatusBytes.FILE_OR_APP_NOT_FOUND:
                Global.logger.error("User does not recognize AID")
            await self.failure_process()
            raise error
        except InvalidResponseError as error:
            await self.failure_process()
            raise error

        Global.logger.info("Handling SELECT response")
        if response.compl_aid == EXPEDITED_PHASE_AID:
            Global.logger.info(
                "AID valid for expedited phase: {!r}".format(
                    hexlify(response.compl_aid)
                )
            )
        elif response.compl_aid == STEPUP_PHASE_AID:
            Global.logger.info(
                "AID valid for step-up phase: {!r}".format(hexlify(response.compl_aid))
            )
        else:
            raise AccessProtocolError("User send unknown AID")

        if response.type != CSA_APPLICATION_TYPE:
            raise AccessProtocolError("User send unknown application type")
        else:
            Global.logger.info(
                "Application type valid (CSA application): 0x{:04x}".format(
                    response.type
                )
            )

        if PROTOCOL_VERSION not in response.expedited_phase_supported_protocol_versions:
            raise AccessProtocolError(
                "User does not support protocol version used by reader"
            )
        else:
            Global.logger.info(
                "Protocol versions ({}) contains valid version: 0x{:04x}".format(
                    ", ".join(
                        str(hex(x))
                        for x in response.expedited_phase_supported_protocol_versions
                    ),
                    PROTOCOL_VERSION,
                )
            )

        self.session.set_select_info(response)
        Global.logger.info("Handling SELECT response done")

    async def handle_auth0(
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

        if (
            transaction_type == Transaction.FAST
            and not self.fast_transaction_implemented
        ):
            raise AccessProtocolError("Requested fast transaction but does not support")

        Global.logger.info(
            "Start handling AUTH0 with transaction type: {} and "
            "transaction code: {}".format(transaction_type.name, transaction_code.name)
        )
        try:
            auth0_response = await self.command_auth0(
                transaction=transaction_type,
                transaction_code=transaction_code,
                protocol_version=PROTOCOL_VERSION,
                reader_epubk=self.session.get_reader_epubkey().as_bytes(),
                transaction_identifier=self.session.transaction_identifier,
                reader_identifier=self.reader_identifier,
                vendor_extension=self.vendor_extension,
            )
        except InvalidResponseError as error:
            await self.failure_process()
            raise error

        Global.logger.info("Handling AUTH0 response")
        Global.logger.info("Checking credential ephemeral public key")
        try:
            credential_ephemeral_public_key = PublicKey(auth0_response.credential_epubk)
        except InvalidKeyError as error:
            raise AccessProtocolError(
                "invalid credential ephemeral public key received: {!r}".format(
                    hexlify(auth0_response.credential_epubk)
                )
            ) from error
        Global.logger.info("Credential ephemeral public key is a valid key")

        Global.logger.info("Saving Auth0 response data to session")
        self.session.set_flag(transaction_type, transaction_code)
        self.session.set_credential_ephemeral_key(credential_ephemeral_public_key)
        self.session.set_response_vendor_extension(
            auth0_response.vendor_specific_extensions
        )

        if transaction_type == Transaction.STANDARD:
            if auth0_response.cryptogram is not None:
                await self.failure_process()
                raise AccessProtocolError(
                    "User send cryptogram during a standard transaction"
                )
            else:
                Global.logger.info(
                    "No cryptogram send during a standard transaction (as expected)"
                )
        else:
            await self.decrypt_cryptogram(auth0_response.cryptogram)

        Global.logger.info("Handling AUTH0 command done")

    async def decrypt_cryptogram(self, cryptogram: bytes | None) -> None:
        if self.session is None:
            raise SessionError("No Session")

        if cryptogram is None:
            await self.failure_process()
            raise AccessProtocolError(
                "User did not send cryptogram during a fast transaction"
            )

        Global.logger.info(
            "Trying to decrypt cryptogram received: {!r}".format(
                hexlify(cryptogram[:-AUTHENTICATION_TAG_SIZE])
            )
        )
        Global.logger.info(
            "With authentication tag: {!r}".format(
                hexlify(cryptogram[-AUTHENTICATION_TAG_SIZE:])
            )
        )
        for entry in self.storage.get_kpersistent_list():
            self.session.derive_key_volatile_fast(
                self.transport_protocol_type,
                entry.access_credential,
                entry.kpersistent,
            )
            Global.logger.info(
                "trying cryptogram secret key: {!r}".format(
                    hexlify(self.session.cryptogram_SK)
                )
            )
            try:
                decrypted_cryptogram = decrypt_cryptogram(
                    self.session.cryptogram_SK,
                    cryptogram[:-AUTHENTICATION_TAG_SIZE],
                    cryptogram[-AUTHENTICATION_TAG_SIZE:],
                )
                Global.logger.info(
                    "decryption successful with: {!r}".format(
                        hexlify(self.session.cryptogram_SK)
                    )
                )
                Global.logger.info(
                    "decrypted cryptogram: {!r}".format(hexlify(decrypted_cryptogram))
                )
                self.session.set_cryptogram_info(TLV.from_bytes(decrypted_cryptogram))
                return
            except VerificationError:
                Global.logger.info("decryption failed, trying next key in storage")
                pass

        raise CryptogramNotFound("Matching Cryptogram not found")

    async def handle_load_cert(self) -> None:
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

        if self.reader_cert is None:
            raise AccessProtocolError("No reader cert available")

        Global.logger.info("Start handling LOAD CERT")
        try:
            await self.command_load_cert(self.reader_cert.encode_compressed())
        except InvalidResponseError as error:
            await self.failure_process()
            raise error

        Global.logger.info("Handling LOAD CERT response")
        Global.logger.info("Handling LOAD CERT response done")

    async def handle_auth1(
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

        Global.logger.info(
            "Start handling AUTH1 with key type request: {}".format(
                expected_response.name
            )
        )
        try:
            auth1_response = await self.command_auth1(
                expected_response=expected_response,
                reader_identifier=self.reader_identifier,
                credential_epubk=self.session.credential_ephemeral_key,
                reader_epubk=self.session.get_reader_epubkey(),
                transaction_identifier=self.session.transaction_identifier,
                encryption=self.session.encryption,
            )
        except (InvalidResponseError, VerificationError) as error:
            await self.failure_process()
            raise error

        Global.logger.info("Handling AUTH1 response")
        Global.logger.info("Checking AUTH1 response fields")
        await self.handle_auth1_credential_public_key(
            expected_response,
            auth1_response.credential_public_key,
            auth1_response.key_slot,
        )

        if not self.session.check_user_device_authentication(
            auth1_response.user_device_signature
        ):
            await self.failure_process()
            raise AccessProtocolError("User device signature authentication failed")
        else:
            Global.logger.info("User device signature authentication succeeded")

        if self.fast_transaction_implemented:
            Global.logger.info("Adding Kpersistent")
            fast_cache_entry = self.storage.add_kpersistent(
                self.session.credential_pubk,
                self.session.derive_key_persistent(
                    self.transport_protocol_type, self.session.credential_pubk
                ),
            )
            Global.logger.info("added fast cache entry:")
            fast_cache_entry.print_to_log()

        Global.logger.info("Save AUTH1 response data to session")
        self.session.set_auth1_info(auth1_response)

        Global.logger.info("Handling AUTH1 response done")

    async def handle_auth1_credential_public_key(
        self,
        expected_response: int,
        credential_public_key_bytes: bytes | None,
        key_slot: bytes | None,
    ) -> None:
        if self.session is None:
            raise SessionError("No Session")

        if expected_response == Auth1Response.CREDENTIAL_PUBLIC_KEY:
            Global.logger.info("Key type request is access credential public key")
            if credential_public_key_bytes is None:
                await self.failure_process()
                raise AccessProtocolError(
                    "Requested credential public key, but none was received"
                )
            if key_slot is not None:
                await self.failure_process()
                raise AccessProtocolError(
                    "Requested credential public key, but key slot was received"
                )
            else:
                Global.logger.info("no key slot present, as required")
            credential_public_key = PublicKey(credential_public_key_bytes)
            Global.logger.info("Access credential public key is a valid key")
        elif expected_response == Auth1Response.KEY_SLOT:
            Global.logger.info("Key type request is key slot")
            if key_slot is None:
                await self.failure_process()
                raise AccessProtocolError("Requested keyslot, but none was received")
            if credential_public_key_bytes is not None:
                await self.failure_process()
                raise AccessProtocolError(
                    "Requested keyslot, but credential public key was received"
                )
            else:
                Global.logger.info("no credential public key present, as required")
            credential_public_key = self.session.lookup_credential_public_key(key_slot)
            Global.logger.info(
                "Access credential public key could be found with key slot"
            )
        self.session.set_credential_public_key(credential_public_key)

    async def handle_control_flow(self, success: bool) -> None:
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

        if success:
            s1 = 0x01
        else:
            s1 = 0x00
        s2 = 0x00

        Global.logger.info(
            "Start handling CONTROL FLOW with s1: 0x{:02x} and s2: 0x{:02x}".format(
                s1, s2
            )
        )
        try:
            await self.command_control_flow(s1, s2)
        except (InvalidResponseError, VerificationError) as error:
            await self.failure_process()
            raise error

        Global.logger.info("Handling AUTH1 response")
        self.session = None
        Global.logger.info("Handling AUTH1 response done")

    async def handle_exchange(
        self,
        atomic_session: bool,
        read_requests: list[tuple[int, int]] | None = None,
        write_requests: list[tuple[int, bytes]] | None = None,
        set_requests: list[tuple[int, int, int]] | None = None,
        notify: TLV | None = None,
        ursk: bytes | None = None,
        update_doc: bytes | None = None,
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

        Global.logger.info(
            "Start handling EXCHANGE with atomic session: {}".format(atomic_session)
        )

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

        try:
            response = await self.command_exchange(
                atomic_session, payload_tlv, self.session.encryption
            )
        except (InvalidResponseError, VerificationError) as error:
            await self.failure_process()
            raise error

        Global.logger.info("Handling EXCHANGE response")
        if response.status_code != bytes.fromhex("00020000"):
            await self.failure_process()
            raise AccessProtocolError(
                "EXCHANGE returned error status at end of payload: {!r}".format(
                    response.status_code
                )
            )
        Global.logger.info(
            "All requests handled successfully, status: {!r}".format(
                response.status_code
            )
        )

        Global.logger.info("Checking read data")
        if len(response.read_data) == 0:
            if read_requests is not None and len(read_requests) != 0:
                raise AccessProtocolError(
                    "Send EXCHANGE command with read requests, but no read data found "
                    "in response"
                )
            else:
                Global.logger.info("No read data found, as expected")
        else:
            read_data = []
            index = 0
            while index < len(response.read_data):
                length = int.from_bytes(response.read_data[index : index + 2], "big")
                data = response.read_data[index + 2 : index + 2 + length]
                read_data.append(data)
                index = index + 2 + length
                Global.logger.info("Read data found: {!r}".format(hexlify(data)))
            if read_requests is None or len(read_requests) != len(read_data):
                raise AccessProtocolError(
                    "Number of read requests in EXCHANGE command ({}) differs from "
                    "number of read data in response ({})".format(
                        len(read_requests), len(read_data)
                    )
                )

        Global.logger.info("Handling EXCHANGE response done")

        return read_data

    async def command_auth0(
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
        Create and send a auth0 command, and wait for a response.

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

        Global.logger.info("Sending AUTH0 command")
        await self.transport_protocol.send_message(
            command.to_bytes(), MessageType.REQUEST
        )

        Global.logger.info("Waiting for AUTH0 response")
        response_str = await self.transport_protocol.get_message()
        Global.logger.info("Received response")
        response = self.apdu.parse_response(response_str, INS.AUTH0)

        return response

    async def command_auth1(
        self,
        expected_response: Auth1Response,
        reader_identifier: bytes,
        credential_epubk: PublicKey,
        reader_epubk: PublicKey,
        transaction_identifier: bytes,
        encryption: EncryptionEngine | None = None,
    ) -> Response:
        """
        Create and send a auth1 command, and wait for a response.

        Args:
            expected_response (Auth1Response): key slot or credential public key
            reader_identifier (bytes):
            credential_epubk (PublicKey):
            reader_epubk (PublicKey):
            transaction_identifier (bytes):
            encryption (EncryptionEngine | None, optional): Encryption engine to
            decrypt the response.
            Response will not be decrypted if this is None. Defaults to None.

        Returns:
            Response: Response containing the received data.
        """
        Global.logger.info("Creating reader authentication data signature")
        data = create_reader_authentication(
            reader_identifier, credential_epubk, reader_epubk, transaction_identifier
        )
        reader_sig = self.reader_key.sign(data.to_bytes())
        Global.logger.debug(
            "reader authentication data signature: {!r}".format(hexlify(reader_sig))
        )
        command = self.apdu.create_auth1_command(expected_response, reader_sig)

        Global.logger.info("Sending AUTH1 command")
        await self.transport_protocol.send_message(
            command.to_bytes(), MessageType.REQUEST
        )

        Global.logger.info("Waiting for AUTH1 response")
        response_str = await self.transport_protocol.get_message()
        Global.logger.info("Received response")
        response = self.apdu.parse_response(response_str, INS.AUTH1, encryption)

        return response

    async def command_select(self, aid: bytes) -> Response:
        """
        Create and send a select command, and wait for a response.

        Args:
            aid (bytes): AID to be send.

        Returns:
            Response: Response containing the received data.
        """
        command = self.apdu.create_select_command(aid)

        Global.logger.info("Sending SELECT command")
        await self.transport_protocol.send_message(
            command.to_bytes(), MessageType.REQUEST
        )

        Global.logger.info("Waiting for SELECT response")
        response_str = await self.transport_protocol.get_message()
        Global.logger.info("Received response")
        response = self.apdu.parse_response(response_str, INS.SELECT)

        return response

    def command_envelope(self) -> None:
        raise NotImplementedError

    def command_get_response(self) -> None:
        raise NotImplementedError

    async def command_load_cert(self, compressed_cert: bytes) -> Response:
        """
        Create and send a load_cert command, and wait for a response.

        Args:
            compressed_cert (bytes): compressed certificate to send.

        Returns:
            Response: Response containing the received data.
        """
        command = self.apdu.create_load_cert_command(compressed_cert)

        Global.logger.info("Sending LOAD CERT command")
        await self.transport_protocol.send_message(
            command.to_bytes(), MessageType.REQUEST
        )

        Global.logger.info("Waiting for LOAD CERT response")
        response_str = await self.transport_protocol.get_message()
        Global.logger.info("Received response")
        response = self.apdu.parse_response(response_str, INS.LOAD_CERT)

        return response

    async def command_exchange(
        self, atomic_session: bool, payload: TLV, encryption: EncryptionEngine
    ) -> Response:
        """
        Create and send a exchange command, and wait for a response.

        Args:
            atomic_session (bool): if True, this is part of an atomic session
            payload (TLV): The payload to send.
            encryption (EncryptionEngine): Encryption engine to encrypt the message
            and decode the response.

        Returns:
            Response: Response containing the received data.
        """
        command = self.apdu.create_exchange_command(atomic_session, payload, encryption)

        Global.logger.info("Sending EXCHANGE command")
        await self.transport_protocol.send_message(
            command.to_bytes(), MessageType.REQUEST
        )

        Global.logger.info("Waiting for EXCHANGE response")
        response_str = await self.transport_protocol.get_message()
        Global.logger.info("Received response")
        response = self.apdu.parse_response(response_str, INS.EXCHANGE, encryption)

        return response

    async def command_control_flow(
        self, s1: int, s2: int, domain_specific_data: bytes | None = None
    ) -> Response:
        """
        Create and send a exchange command, and wait for a response.

        Args:
            s1 (int):
            s2 (int):
            domain_specific_data (bytes | None, optional): Defaults to None.

        Returns:
            Response: Response containing the received data.
        """
        command = self.apdu.create_control_flow_command(s1, s2, domain_specific_data)

        Global.logger.info("Sending CONTROL FLOW command")
        await self.transport_protocol.send_message(
            command.to_bytes(), MessageType.REQUEST
        )

        Global.logger.info("Waiting for CONTROL FLOW response")
        response_str = await self.transport_protocol.get_message()
        Global.logger.info("Received response")
        response = self.apdu.parse_response(response_str, INS.CONTROL_FLOW)

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

    def set_initiate_access_protocol_info(
        self, initiate_access_protocol_notification: bytes
    ) -> None:
        Global.logger.debug(
            "Initiate access protocol TLV: {!r}".format(
                hexlify(initiate_access_protocol_notification)
            )
        )
        try:
            self.proprietary_tlv = TLV.from_bytes(initiate_access_protocol_notification)
        except TlvError as error:
            raise UnexpectedNotificationDataError(
                initiate_access_protocol_notification,
                "Proprietary information is not a valid TLV",
            ) from error

        try:
            type_bytes = self.proprietary_tlv.get_bytes(Select.TYPE_TAG)
            if len(type_bytes) != Select.TYPE_LEN:
                raise UnexpectedNotificationDataError(
                    initiate_access_protocol_notification, "Type has invalid length"
                )
            self.application_type = int.from_bytes(type_bytes, byteorder="big")
            Global.logger.debug("type: {}".format(self.application_type))
        except IndexError as error:
            raise UnexpectedNotificationDataError(
                initiate_access_protocol_notification,
                "missing Type, tag: {:#x}".format(error.args[0]),
            ) from error

        try:
            etspv_bytes = self.proprietary_tlv.get_bytes(Select.ETSPV_TAG)
            if (len(etspv_bytes) % 2) == 1:
                raise UnexpectedNotificationDataError(
                    initiate_access_protocol_notification,
                    "expedited_phase_supported_protocol_versions has invalid length",
                )
            self.expedited_phase_supported_protocol_versions = (
                Message._data_to_2byte_list(etspv_bytes)
            )
            Global.logger.debug(
                "expedited transaction supported protocol versions: {}".format(
                    self.expedited_phase_supported_protocol_versions
                )
            )
        except IndexError as error:
            raise UnexpectedNotificationDataError(
                initiate_access_protocol_notification,
                "missing expedited_phase_supported_protocol_versions, tag: {:#x}".format(
                    error.args[0]
                ),
            ) from error

        self.maximum_command_apdu = None
        self.maximum_response_apdu = None
        try:
            extended_length = self.proprietary_tlv.get_tlv(Select.EXTENDED_INFO_TAG)
            if len(extended_length.to_bytes()) != Select.EXTENDED_INFO_LEN:
                raise UnexpectedNotificationDataError(
                    initiate_access_protocol_notification,
                    "Extended Length Information has invalid length",
                )
            try:
                self.maximum_command_apdu = int.from_bytes(
                    extended_length.get_bytes(Select.MAX_COMMAND_TAG, index=0), "big"
                )
            except IndexError as error:
                raise UnexpectedNotificationDataError(
                    initiate_access_protocol_notification,
                    "missing Maximum Command APDU, tag: {:#x}".format(error.args[0]),
                ) from error
            try:
                self.maximum_response_apdu = int.from_bytes(
                    extended_length.get_bytes(Select.MAX_RESPONSE_TAG, index=1), "big"
                )
            except IndexError as error:
                raise UnexpectedNotificationDataError(
                    initiate_access_protocol_notification,
                    "missing Maximum response, tag: {:#x}".format(error.args[0]),
                ) from error
        except IndexError:
            pass
        Global.logger.debug(
            "maximum command apdu: {}".format(self.maximum_command_apdu)
        )
        Global.logger.debug(
            "maximum response apdu: {}".format(self.maximum_response_apdu)
        )

        self.vendor_specific_extensions = None
        try:
            self.vendor_specific_extensions = self.proprietary_tlv.get_tlv(
                Select.VENDOR_SPECIFIC_TAG
            )
            Global.logger.debug(
                "vendor specific extensions: {!r}".format(
                    hexlify(self.vendor_specific_extensions.to_bytes())
                )
            )
        except IndexError:
            pass
        except TlvError as error:
            raise UnexpectedNotificationDataError(
                initiate_access_protocol_notification,
                "Vendor specific extensions is not a valid TLV",
            ) from error

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

    def set_response_vendor_extension(self, vendor_extension: TLV | None) -> None:
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

    def set_cryptogram_info(
        self,
        decrypted_cryptogram: TLV,
    ) -> None:
        self.signaling_bitmap = decrypted_cryptogram.get_bytes(
            Auth1.SIGNALING_BITMAP_TAG
        )
        self.credential_signed_timestamp = decrypted_cryptogram.get_bytes(
            Auth1.CREDENTIAL_TIMESTAMP_TAG
        )
        self.revocation_signed_timestamp = decrypted_cryptogram.get_bytes(
            Auth1.REVOCATION_TIMESTAMP_TAG
        )

    def set_auth1_info(
        self,
        auth1_response: Response,
    ) -> None:
        self.private_mailbox_data = auth1_response.private_mailbox_data
        self.signaling_bitmap = auth1_response.signaling_bitmap
        self.credential_signed_timestamp = auth1_response.credential_signed_timestamp
        self.revocation_signed_timestamp = auth1_response.revocation_signed_timestamp

    def check_user_device_authentication(self, user_device_signature: bytes) -> bool:
        Global.logger.info("Checking credential authentication data")
        data = create_user_device_authentication(
            self.reader_identifier,
            self.credential_ephemeral_key,
            self.reader_ephemeral.get_public_key(),
            self.transaction_identifier,
        )
        Global.logger.debug(
            "verifying user data with key: {!r}".format(
                hexlify(self.credential_pubk.as_bytes())
            )
        )
        Global.logger.debug(
            "verifying user data with signature: {!r}".format(
                hexlify(user_device_signature)
            )
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
        Global.logger.debug("Deriving key (volatile)")

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
        Global.logger.debug(
            "exchange SK reader: {!r}".format(hexlify(self.exchange_SK_reader))
        )
        Global.logger.debug(
            "exchange SK device: {!r}".format(hexlify(self.exchange_SK_device))
        )
        Global.logger.debug("step up SK: {!r}".format(hexlify(self.step_up_SK)))
        Global.logger.debug("ble SK: {!r}".format(hexlify(self.ble_SK)))
        Global.logger.debug("UR SK: {!r}".format(hexlify(self.UR_SK)))

        self.encryption = EncryptionEngine(
            DeviceType.READER, self.exchange_SK_reader, self.exchange_SK_device
        )

    def derive_key_volatile_fast(
        self,
        transport_protocol: TransportProtocol,
        credential: PublicKey,
        k_persistent: bytes,
    ) -> None:
        Global.logger.debug("Deriving key (volatile fast)")
        info = bytearray(self.credential_ephemeral_key.get_x().to_bytes(32, "big"))
        if self.command_vendor_extension is not None:
            info.extend(self.command_vendor_extension)
        if self.response_vendor_extension is not None:
            info.extend(self.response_vendor_extension)

        salt = create_salt(
            transport_protocol=transport_protocol,
            word=b"VolatileFast",
            reader_public_key=self.reader_key.get_public_key(),
            reader_ephemeral_public_key=self.reader_ephemeral.get_public_key(),
            reader_identifier=self.reader_identifier,
            protocol_version=PROTOCOL_VERSION.to_bytes(2, "big"),
            transaction_identifier=self.transaction_identifier,
            flag=self.flag,
            proprietary_information=self.proprietary_tlv.to_bytes(),
            credential_ephemeral_public_key=credential,
        )
        derived_key = derive_key(k_persistent, bytes(info), 160, salt)
        self.cryptogram_SK = derived_key[0:32]
        self.exchange_SK_reader = derived_key[32:64]
        self.exchange_SK_device = derived_key[64:96]
        self.ble_SK = derived_key[96:128]
        self.UR_SK = derived_key[128:160]

        Global.logger.debug("cryptogram SK: {!r}".format(hexlify(self.cryptogram_SK)))
        Global.logger.debug(
            "exchange SK reader: {!r}".format(hexlify(self.exchange_SK_reader))
        )
        Global.logger.debug(
            "exchange SK device: {!r}".format(hexlify(self.exchange_SK_device))
        )
        Global.logger.debug("ble SK: {!r}".format(hexlify(self.ble_SK)))
        Global.logger.debug("UR SK: {!r}".format(hexlify(self.UR_SK)))

    def derive_key_persistent(
        self, transport_protocol: TransportProtocol, credential: PublicKey
    ) -> bytes:
        Global.logger.debug("Deriving key (persistent)")
        info = bytearray(self.credential_ephemeral_key.get_x().to_bytes(32, "big"))
        if self.command_vendor_extension is not None:
            info.extend(self.command_vendor_extension)
        if self.response_vendor_extension is not None:
            info.extend(self.response_vendor_extension)

        salt = create_salt(
            transport_protocol=transport_protocol,
            word=b"Persistent**",
            reader_public_key=self.reader_key.get_public_key(),
            reader_ephemeral_public_key=self.reader_ephemeral.get_public_key(),
            reader_identifier=self.reader_identifier,
            protocol_version=PROTOCOL_VERSION.to_bytes(2, "big"),
            transaction_identifier=self.transaction_identifier,
            flag=self.flag,
            proprietary_information=self.proprietary_tlv.to_bytes(),
        )
        derived_key = derive_key(self.shared_key, bytes(info), 32, salt)
        return derived_key[0:32]

    def encrypt_payload(self, payload: bytes) -> tuple[bytes, bytes]:
        return self.encryption.encrypt(payload)

    def decrypt_payload(
        self, encrypted_payload: bytes, authentication_tag: bytes
    ) -> bytes:
        return self.encryption.decrypt(encrypted_payload, authentication_tag)


class ReaderFastCacheEntry:
    def __init__(
        self,
        access_credential: PublicKey,
        kpersistent: bytes,
    ):
        self.access_credential = access_credential
        self.kpersistent = kpersistent

    def print_to_log(self) -> None:
        Global.logger.info(
            "access credential: {!r}".format(hexlify(self.access_credential.as_bytes()))
        )
        Global.logger.info("kpersistent: {!r}".format(hexlify(self.kpersistent)))
