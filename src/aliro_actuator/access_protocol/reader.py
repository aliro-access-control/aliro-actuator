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
from enum import Enum

from aliro_actuator import READER_GROUP_ID_LENGTH, READER_GROUP_SUB_ID_LENGTH, Global
from aliro_actuator.access_protocol.apdu import (
    AUTHENTICATION_TAG_SIZE,
    INS,
    S1,
    S2,
    Auth1Response,
    AuthenticationPolicy,
    ReaderStatus,
    Response,
    StatusBytes,
    Transaction,
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
    TransportProtocol,
)
from aliro_actuator.access_protocol.device import Device
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
    UnexpectedBLEMessageError,
)
from aliro_actuator.access_protocol.tlv import TLV
from aliro_actuator.transport_protocol import Mode, TransportProtocolBase
from aliro_actuator.transport_protocol.ble_encryption import get_ble_encryption
from aliro_actuator.transport_protocol.ble_message_format import (
    AP_ID,
    BleMessage,
    GeneralError_Values,
    Notification_ID,
    OperationSourceInformation_Values,
    ProtocolType,
    ReaderStatusInformation_Values,
    Supplementary_Service_ID,
    UWB_RangingService_ID,
)
from aliro_actuator.transport_protocol.ble_uwb import BLEUWB
from aliro_actuator.transport_protocol.errors import (
    InvalidProtocolTypeError,
    NoDeviceConnectedError,
    UnexpectedMessageTypeError,
)
from aliro_actuator.trust_framework.certificate import Certificate
from aliro_actuator.trust_framework.errors import InvalidKeyError
from aliro_actuator.trust_framework.key import KeyPair, PublicKey, derive_key
from aliro_actuator.trust_framework.key_slot import get_key_slot
from aliro_actuator.trust_framework.reader_identifier import ReaderIdentifier


class ReaderState(Enum):
    EXPEDITED = 1
    STEPUP = 2


class FastTransactionHandling(Enum):
    CONTINUE_WITH_STANDARD = 0
    ABORT_TRANSACTION = 1


class ReaderMode(Enum):
    TEST = 0  # Every error raises an Exception
    READER = 1  # Strictly follows spec, may ignore errors if so noted in the spec, and
    # sends failure messages


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
        fast_transaction_handling (FastTransactionHandling): how to handle a failed
        fast transaction

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
        key_slot_list: list[PublicKey] = [],
        fast_transaction_handling: FastTransactionHandling = FastTransactionHandling.CONTINUE_WITH_STANDARD,
        reader_system_issuer_ca: PublicKey | None = None,
        mode: ReaderMode = ReaderMode.TEST,
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
        self.reader_system_issuer_ca = reader_system_issuer_ca

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

        Global.logger.debug("Creating key slot list")
        self.key_slot_list = []
        for key in key_slot_list:
            key_slot = get_key_slot(key)
            self.key_slot_list.append((key_slot, key))
            Global.logger.debug(
                "Adding entry: key slot: {!r}, key: {!r}".format(
                    hexlify(key_slot), hexlify(key.as_bytes())
                )
            )

        self.fast_transaction_handling = fast_transaction_handling
        self.failure_process_started = False
        self.mode = mode

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
        self, authentication_policy: AuthenticationPolicy
    ) -> None:
        Global.logger.info("Start Expedited Transaction (fast)")
        try:
            await self.handle_auth0(Transaction.FAST, authentication_policy)
        except CryptogramNotFound as error:
            if (
                self.fast_transaction_handling
                == FastTransactionHandling.CONTINUE_WITH_STANDARD
            ):
                await self.handle_auth1()
            else:
                raise error
        Global.logger.info("Expedited Transaction (fast) Done")

    async def expedited_transaction_standard(
        self, authentication_policy: AuthenticationPolicy, load_cert: bool = False
    ) -> None:
        """
        Runs the Expedited Standard Phase.

        Args:
            authentication_policy (AuthenticationPolicy): Passed during AUTH0.
            load_cert (bool, optional): Runs the load_cert command if True.
            Defaults to False.
        """
        Global.logger.info("Start Expedited Transaction (standard)")
        await self.handle_auth0(Transaction.STANDARD, authentication_policy)
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

        self.failure_process_started = False

    def end_session(self) -> None:
        """
        End the current reader session.
        """
        Global.logger.info("Ending session")
        self.session = None

    async def failure_process(self, error_code: int = 0x00) -> None:
        """
        Should be called when a failure state has occurred.
        Destroys all session bound keys and data.
        If transport protocol is NFC, a control_flow command indicating failure is send.
        If transport protocol is BLE, a failure event message is send.
        """
        if self.failure_process_started:
            # we are already handling a failure, don't send another failure message
            return
        self.failure_process_started = True

        if self.mode == ReaderMode.READER:
            if (
                self.transport_protocol_type == TransportProtocol.NFC
                or self.transport_protocol_type == TransportProtocol.SOCKET_NFC
            ):
                if self.session is None or self.session.encryption_expedited is None:
                    s2 = S2(error_code)
                    await self.handle_control_flow(s2)
                else:
                    await self.handle_exchange(False, reader_status=error_code)
            if (
                self.transport_protocol_type == TransportProtocol.BLE_UWB
                or self.transport_protocol_type == TransportProtocol.SOCKET_BLE
            ):
                await self.handle_error_event_ble_message(
                    GeneralError_Values.UNKNOWN_ERROR
                )
                pass

        await self.transaction_termination()

    async def wait_for_initiate_access_protocol_notification(self) -> None:
        if self.session is None:
            raise SessionError("No Session")

        Global.logger.info("Waiting for Initiate access protocol notification")
        response_str, header, id = await self.transport_protocol.get_message()
        if (
            header != ProtocolType.NOTIFICATION
            or id != Notification_ID.INITIATE_ACCESS_PROTOCOL
        ):
            raise UnexpectedBLEMessageError(
                "Received unexpected ble message while waiting for "
                "initiate_access_protocol message",
                header,
                id,
            )

        message = BleMessage(header, id, response_str)
        message.parse_payload(self.session.get_ble_encryption())

        self.session.set_initiate_access_protocol_info(message)

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

    async def handle_error_event_ble_message(self, error_code: int) -> None:
        if self.session is None:
            raise SessionError("No Session")

        message = BleMessage.create_error_event_message(
            error_code, self.session.get_ble_encryption()
        )
        await self.transport_protocol.send_message(message)

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
            await self.failure_process(S2.NONE)
            raise error
        except InvalidResponseError as error:
            await self.failure_process(S2.NONE)
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
            await self.failure_process(S2.NONE)
            raise AccessProtocolError("User send unknown AID")

        if response.type != CSA_APPLICATION_TYPE:
            await self.failure_process(S2.NONE)
            raise AccessProtocolError("User send unknown application type")
        else:
            Global.logger.info(
                "Application type valid (CSA application): 0x{:04x}".format(
                    response.type
                )
            )

        if PROTOCOL_VERSION not in response.expedited_phase_supported_protocol_versions:
            await self.failure_process(S2.PROTOCOL_VERSION_NOT_SUPPORTED)
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
        self, transaction_type: Transaction, authentication_policy: AuthenticationPolicy
    ) -> None:
        """
        Create and send a AUTH0 command.
        Required data from is retrieved from the Reader (self) and the session.
        The data contained in the response is stored in the session.

        Args:
            transaction_type (Transaction): fast or standard
            authentication_policy (AuthenticationPolicy): code with instruction (ex. Lock/Unlock)

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
            "Authentication policy: {}".format(
                transaction_type.name, authentication_policy.name
            )
        )
        try:
            auth0_response = await self.command_auth0(
                transaction=transaction_type,
                authentication_policy=authentication_policy,
                protocol_version=PROTOCOL_VERSION,
                reader_epubk=self.session.get_reader_epubkey().as_bytes(),
                transaction_identifier=self.session.transaction_identifier,
                reader_identifier=self.reader_identifier,
                vendor_extension=self.vendor_extension,
            )
        except InvalidResponseError as error:
            await self.failure_process(S2.NONE)
            raise error

        Global.logger.info("Handling AUTH0 response")
        Global.logger.info("Checking access credential ephemeral public key")
        try:
            credential_ephemeral_public_key = PublicKey(auth0_response.credential_epubk)
        except InvalidKeyError as error:
            await self.failure_process(S2.NONE)
            raise AccessProtocolError(
                "invalid access credential ephemeral public key received: {!r}".format(
                    hexlify(auth0_response.credential_epubk)
                )
            ) from error
        Global.logger.info("Access credential ephemeral public key is a valid key")

        Global.logger.info("Saving Auth0 response data to session")
        self.session.set_flag(transaction_type, authentication_policy)
        self.session.set_credential_ephemeral_key(credential_ephemeral_public_key)
        self.session.set_response_vendor_extension(
            auth0_response.vendor_specific_extensions
        )

        if transaction_type == Transaction.STANDARD:
            if auth0_response.cryptogram is not None:
                await self.failure_process(S2.NONE)
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
            await self.failure_process(S2.NONE)
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
                self.session.set_credential_public_key(entry.access_credential)
                self.session.create_encryption_engine_expedited()
                if self.transport_protocol_type in [
                    TransportProtocol.BLE_UWB,
                    TransportProtocol.SOCKET_BLE,
                ]:
                    Global.logger.info("Setting up BLE encryption")
                    self.session.set_ble_encryption(self.transport_protocol)
                return
            except VerificationError:
                Global.logger.info("decryption failed, trying next key in storage")
                pass

        if self.fast_transaction_handling == FastTransactionHandling.ABORT_TRANSACTION:
            await self.failure_process(S2.NONE)
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
            await self.failure_process(S2.NONE)
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

        self.create_shared_keys()

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
                encryption=self.session.encryption_expedited,
            )
        except (InvalidResponseError, VerificationError) as error:
            await self.failure_process(ReaderStatus.INVALID_DATA_FORMAT)
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
            await self.failure_process(ReaderStatus.INVALID_SIGNATURE)
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

    def create_shared_keys(self) -> None:
        if self.session is None:
            raise SessionError("No Session")

        Global.logger.info("Create shared keys")
        self.session.set_shared_key()
        self.session.derive_key_volatile(self.transport_protocol_type)
        if self.transport_protocol_type in [
            TransportProtocol.BLE_UWB,
            TransportProtocol.SOCKET_BLE,
        ]:
            Global.logger.info("Setting up BLE encryption")
            self.session.set_ble_encryption(self.transport_protocol)

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
                await self.failure_process(ReaderStatus.NO_PUBLIC_KEY_IN_RESPONSE)
                raise AccessProtocolError(
                    "Requested credential public key, but none was received"
                )
            if key_slot is not None:
                await self.failure_process(ReaderStatus.INVALID_DATA_FORMAT)
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
                await self.failure_process(ReaderStatus.NO_KEY_SLOT_IN_RESPONSE)
                raise AccessProtocolError("Requested keyslot, but none was received")
            if credential_public_key_bytes is not None:
                await self.failure_process(ReaderStatus.INVALID_DATA_FORMAT)
                raise AccessProtocolError(
                    "Requested keyslot, but credential public key was received"
                )
            else:
                Global.logger.info("no credential public key present, as required")
            credential_public_key = self.lookup_credential_public_key(key_slot)
            Global.logger.info(
                "Access credential public key could be found with key slot"
            )
        self.session.set_credential_public_key(credential_public_key)

    def lookup_credential_public_key(self, key_slot: bytes) -> PublicKey:
        Global.logger.info("Looking up Credential public key using key slot")
        Global.logger.debug("Looking for key slot: {!r}".format(hexlify(key_slot)))
        Global.logger.debug(
            "Saved key slots: [{!r}]".format(
                ", ".join(str(hexlify(x[0])) for x in self.key_slot_list)
            )
        )
        valid_keys = [item[1] for item in self.key_slot_list if item[0] == key_slot]
        if len(valid_keys) > 1:
            raise AccessProtocolError("Multiple keys with the same key slot")
        if len(valid_keys) == 0:
            raise AccessProtocolError("No keys with the requested key slot")
        return valid_keys[0]

    async def handle_control_flow(self, s2: S2) -> None:
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

        s1 = S1.FINISHED_WITH_FAILURE
        s2 = s2

        Global.logger.info(
            "Start handling CONTROL FLOW with s1: 0x{:02x} and s2: 0x{:02x}".format(
                s1, s2
            )
        )
        try:
            await self.command_control_flow(s1, s2)
        except (InvalidResponseError, VerificationError) as error:
            await self.failure_process(ReaderStatus.INVALID_DATA_FORMAT)
            raise error

        Global.logger.info("Handling AUTH1 response")
        self.session = None
        Global.logger.info("Handling AUTH1 response done")

    async def handle_exchange(
        self,
        atomic_session: bool = False,
        read_requests: list[tuple[int, int]] | None = None,
        write_requests: list[tuple[int, bytes]] | None = None,
        set_requests: list[tuple[int, int, int]] | None = None,
        notify: TLV | None = None,
        ursk: bool = False,
        update_doc: bytes | None = None,
        reader_status: int | None = None,
        reader_state: ReaderState = ReaderState.EXPEDITED,
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

        Global.logger.info("Start handling EXCHANGE")

        Global.logger.debug("Creating mailbox commands TLV")
        mailbox_commands_list: list[tuple[int, bytes | list]] = []
        if read_requests is not None:
            Global.logger.debug("Adding read requests")
            for read_request in read_requests:
                mailbox_commands_list.append(
                    (
                        Exchange.READ_TAG,
                        read_request[0].to_bytes(2, "big")
                        + read_request[1].to_bytes(2, "big"),
                    )
                )
        if write_requests is not None:
            for write_request in write_requests:
                mailbox_commands_list.append(
                    (
                        Exchange.WRITE_TAG,
                        write_request[0].to_bytes(2, "big") + write_request[1],
                    )
                )
        if set_requests is not None:
            Global.logger.debug("Adding set requests")
            for set_request in set_requests:
                mailbox_commands_list.append(
                    (
                        Exchange.SET_TAG,
                        set_request[0].to_bytes(2, "big")
                        + set_request[1].to_bytes(2, "big")
                        + set_request[2].to_bytes(1, "big"),
                    )
                )
        mailbox_commands_tlv = TLV(mailbox_commands_list)
        if len(mailbox_commands_tlv.to_data()) > 0:
            Global.logger.info(
                "mailbox commands are part of an atomic session: {}".format(
                    atomic_session
                )
            )
            mailbox_commands = (
                atomic_session.to_bytes(1, "big") + mailbox_commands_tlv.to_bytes()
            )
            Global.logger.debug("Creating mailbox commands TLV Done")
        else:
            mailbox_commands = None
            Global.logger.debug("No mailbox commands in this EXCHANGE")

        if reader_state == ReaderState.EXPEDITED:
            Global.logger.debug("Using expedited encryption key")
            encryption = self.session.encryption_expedited
        elif reader_state == ReaderState.STEPUP:
            Global.logger.debug("Using step up encryption key")
            encryption = self.session.encryption_stepup

        if notify is not None:
            notify_bytes = notify.to_bytes()
        else:
            notify_bytes = None

        try:
            response = await self.command_exchange(
                mailbox_commands=mailbox_commands,
                notify=notify_bytes,
                reader_status=reader_status,
                ursk=ursk,
                update_doc=update_doc,
                encryption=encryption,
            )
        except (InvalidResponseError, VerificationError) as error:
            await self.failure_process(ReaderStatus.INVALID_DATA_FORMAT)
            raise error

        Global.logger.info("Handling EXCHANGE response")
        if len(response.status_code) != 4:
            await self.failure_process(ReaderStatus.STATUS_WORD_ERROR)
            raise AccessProtocolError(
                "EXCHANGE payload status has invalid length: {!r}".format(
                    response.status_code
                )
            )
        if response.status_code != bytes.fromhex("00020000"):
            await self.failure_process(ReaderStatus.STATUS_WORD_ERROR)
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
        read_data = []
        if len(response.read_data) == 0:
            if read_requests is not None and len(read_requests) != 0:
                raise AccessProtocolError(
                    "Send EXCHANGE command with read requests, but no read data found "
                    "in response"
                )
            else:
                Global.logger.info("No read data found, as expected")
        else:
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

    async def reader_status_status_changed(
        self, operation_source_information: int, reader_status_information: int
    ) -> None:
        """
        Send the BLE message Reader Status Changed.
        """
        if self.session is None:
            raise SessionError("No Session")

        Global.logger.info("Sending Reader Status Changed BLE message")

        message = BleMessage.create_reader_status_changed(
            operation_source_information,
            reader_status_information,
            self.session.get_ble_encryption(),
        )
        await self.transport_protocol.send_message(message)

    async def reader_status_access_protocol_completed(
        self, unsolicited_reader_status_reporting: int, reader_status_information: int
    ) -> None:
        """
        Send the BLE message Reader Status Access Protocol Completed.
        """
        if self.session is None:
            raise SessionError("No Session")

        Global.logger.info(
            "Sending Reader Status Access Protocol Completed BLE message"
        )

        message = BleMessage.create_access_protocol_completed(
            unsolicited_reader_status_reporting,
            reader_status_information,
            self.session.get_ble_encryption(),
        )
        await self.transport_protocol.send_message(message)

    def check_ble_message_type_for_response(
        self, header: int | None, id: int | None
    ) -> None:
        if (header is not None and header != ProtocolType.AP) or (
            id is not None and id != AP_ID.AP_RS
        ):
            raise UnexpectedBLEMessageError(
                "Received unexpected ble message while waiting for "
                "AP response message",
                header,
                id,
            )

    async def command_auth0(
        self,
        transaction: Transaction,
        authentication_policy: AuthenticationPolicy,
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
            authentication_policy (AuthenticationPolicy): code with instruction (ex. Lock/Unlock)
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
            authentication_policy,
            protocol_version,
            reader_epubk,
            transaction_identifier,
            reader_identifier,
            vendor_extension,
        )

        Global.logger.info("Sending AUTH0 command")
        await self.transport_protocol.send_message(command)

        Global.logger.info("Waiting for AUTH0 response")
        response_str, header, id = await self.transport_protocol.get_message()
        self.check_ble_message_type_for_response(header, id)
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
        await self.transport_protocol.send_message(command)

        Global.logger.info("Waiting for AUTH1 response")
        response_str, header, id = await self.transport_protocol.get_message()
        self.check_ble_message_type_for_response(header, id)

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
        await self.transport_protocol.send_message(command)

        Global.logger.info("Waiting for SELECT response")
        response_str, header, id = await self.transport_protocol.get_message()
        self.check_ble_message_type_for_response(header, id)

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
        await self.transport_protocol.send_message(command)

        Global.logger.info("Waiting for LOAD CERT response")
        response_str, header, id = await self.transport_protocol.get_message()
        self.check_ble_message_type_for_response(header, id)

        Global.logger.info("Received response")
        response = self.apdu.parse_response(response_str, INS.LOAD_CERT)

        return response

    async def command_exchange(
        self,
        mailbox_commands: bytes | None = None,
        notify: bytes | None = None,
        reader_status: int | None = None,
        ursk: bool = False,
        update_doc: bytes | None = None,
        encryption: EncryptionEngine | None = None,
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
        command = self.apdu.create_exchange_command(
            mailbox_commands=mailbox_commands,
            notify=notify,
            reader_status=reader_status,
            ursk=ursk,
            update_doc=update_doc,
            encryption=encryption,
        )

        Global.logger.info("Sending EXCHANGE command")
        await self.transport_protocol.send_message(command)

        Global.logger.info("Waiting for EXCHANGE response")
        response_str, header, id = await self.transport_protocol.get_message()
        self.check_ble_message_type_for_response(header, id)

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
        await self.transport_protocol.send_message(command)

        Global.logger.info("Waiting for CONTROL FLOW response")
        response_str, header, id = await self.transport_protocol.get_message()
        self.check_ble_message_type_for_response(header, id)

        Global.logger.info("Received response")
        response = self.apdu.parse_response(response_str, INS.CONTROL_FLOW)

        return response

    async def wait_for_ble_message(
        self,
        encryption: EncryptionEngine | None = None,
    ) -> BleMessage:
        """
        Waits until a ble message is received.

        Args:
            encryption (EncryptionEngine | None, optional): Used for decrypting
            messages.
            Not required for every command. Defaults to None.

        Raises:
            AccessProtocolError: When receiving an unexpected message.

        Returns:
            BleMessage: the received ble message.
        """
        Global.logger.info("Waiting for ble message")
        command_str, header, id = await self.transport_protocol.get_message()
        if header is not None and id is not None:
            Global.logger.info(
                "Received BLE message with header: 0x{:02x} and id: 0x{:02x}".format(
                    header, id
                )
            )
            message = BleMessage(header, id, command_str)
        else:
            raise AccessProtocolError(
                "Received unexpected message while waiting for BLE message : "
                "{!r}".format(hexlify(message.to_bytes()))
            )
        return message

    async def ranging_loop(self) -> None:
        while True:
            try:
                Global.logger.info("Waiting for ranging session setup")
                payload, header, id = await self.transport_protocol.get_message()
                if header is not None and id is not None:
                    message = BleMessage(header, id, payload)
                else:
                    raise UnexpectedMessageTypeError
            except NoDeviceConnectedError:
                break
            if (
                header == ProtocolType.SUPPLEMENTARY_SERVICE
                and id == Supplementary_Service_ID.TIME_SYNC
            ):
                self.handle_timesync(message)
            elif header == ProtocolType.NOTIFICATION and id == Notification_ID.RANGING:
                await self.handle_initiate_ranging(message)
            elif (
                header == ProtocolType.UWB_RANGING_SERVICE
                and id == UWB_RangingService_ID.RANGING_SESSION_SETUP_M2
            ):
                await self.handle_ranging_setup_m2(message)
            elif (
                header == ProtocolType.UWB_RANGING_SERVICE
                and id == UWB_RangingService_ID.RANGING_SESSION_SETUP_M4
            ):
                await self.handle_ranging_setup_m4(message)
                await self.transport_protocol.start_ranging()

                val = await self.transport_protocol.get_ranging_data()
                Global.logger.info(f"Ranging distance: {val}")
                await self.send_ranging_session_suspend_request()
                await self.reader_status_status_changed(
                    ReaderStatusInformation_Values.UNSECURED,
                    OperationSourceInformation_Values.UNSPECIFIED,
                )
            elif (
                header == ProtocolType.UWB_RANGING_SERVICE
                and id == UWB_RangingService_ID.RANGING_SESSION_SUSPEND_REQUEST
            ):
                await self.handle_ranging_session_suspend_request(message)
            elif (
                header == ProtocolType.UWB_RANGING_SERVICE
                and id == UWB_RangingService_ID.RANGING_SESSION_SUSPEND_RESPONSE
            ):
                await self.handle_ranging_session_suspend_response(message)
            elif (
                header == ProtocolType.UWB_RANGING_SERVICE
                and id == UWB_RangingService_ID.RANGING_SESSION_RESUME_REQUEST
            ):
                await self.handle_ranging_session_resume_request(message)
            elif (
                header == ProtocolType.UWB_RANGING_SERVICE
                and id == UWB_RangingService_ID.RANGING_SESSION_RESUME_RESPONSE
            ):
                await self.handle_ranging_session_resume_response(message)
            else:
                raise UnexpectedBLEMessageError(
                    "Received unexpected ble message while waiting for "
                    "Ranging session setup sequence",
                    header,
                    id,
                )

    def handle_timesync(self, message: BleMessage) -> None:
        Global.logger.info("Handling time sync message")
        message.parse_payload(self.session.get_ble_encryption())

    async def handle_initiate_ranging(self, message: BleMessage) -> None:
        Global.logger.info("Handling initiate ranging message")
        message.parse_payload(self.session.get_ble_encryption())
        await self.send_ranging_session_setup_m1()

    async def handle_ranging_setup_m2(self, message: BleMessage) -> None:
        Global.logger.info("Handling ranging session setup message M2")
        message.parse_payload(self.session.get_ble_encryption())
        # TODO: Number Chaps per Slot, Number Responder Nodes, Number Slots per Round,
        await self.transport_protocol.set_ran_multiplier(
            int.from_bytes(message.ran_multiplier.value, "big")
        )

        self.received_sync_code_bitmask = int.from_bytes(
            message.sync_code_index_bitmask.value, "big"
        )

        await self.transport_protocol.set_hopping_mode(0)  # TODO
        await self.transport_protocol.set_mac_mode(0)  # TODO
        await self.send_ranging_session_setup_m3()

    async def handle_ranging_setup_m4(self, message: BleMessage) -> None:
        """
        Finish setting up the ranging session and collect distance measurement
        """
        Global.logger.info("Handling ranging session setup message M4")
        message.parse_payload(self.session.get_ble_encryption())
        await self.transport_protocol.set_sts_index0(
            int.from_bytes(message.sts_index0.value, "big")
        )
        await self.transport_protocol.set_uwb_time0(
            int.from_bytes(message.uwb_time0.value, "big")
        )
        await self.transport_protocol.set_hop_mode_key(
            int.from_bytes(message.hop_mode_key.value, "big")
        )
        await self.transport_protocol.set_sync_code_index(
            int.from_bytes(message.sync_code_index.value, "big")
        )

    async def handle_ranging_session_suspend_request(self, message: BleMessage) -> None:
        Global.logger.info("Handling ranging session suspend request")
        message.parse_payload(self.session.get_ble_encryption())

        await self.send_ranging_session_suspend_response()

    async def handle_ranging_session_suspend_response(
        self, message: BleMessage
    ) -> None:
        Global.logger.info("Handling ranging session suspend response")
        message.parse_payload(self.session.get_ble_encryption())
        await self.transport_protocol.stop_ranging()

    async def handle_ranging_session_resume_request(self, message: BleMessage) -> None:
        Global.logger.info("Handling ranging session resume request")
        message.parse_payload(self.session.get_ble_encryption())

        await self.send_ranging_session_resume_response()

    async def handle_ranging_session_resume_response(self, message: BleMessage) -> None:
        Global.logger.info("Handling ranging session resume response")
        message.parse_payload(self.session.get_ble_encryption())
        await self.transport_protocol.start_ranging()

    async def send_ranging_session_setup_m1(self) -> None:
        if not isinstance(self.transport_protocol, BLEUWB):
            raise InvalidProtocolTypeError

        if self.session is None:
            raise SessionError("No Session")

        Global.logger.info("Sending ranging session setup M1 ble message")

        uwb_configuration_id = self.transport_protocol.get_uwb_config_id_support()
        pulse_shape_combination = (
            self.transport_protocol.get_pulse_shape_combination_support()
        )
        channel_bitmask = self.transport_protocol.get_channel_bitmask()
        uwb_session_id = self.transport_protocol.get_uwb_session_id()
        vendor_specific = 0xFF

        message = BleMessage.create_ranging_session_setup_m1(
            uwb_configuration_id,
            pulse_shape_combination,
            channel_bitmask,
            uwb_session_id,
            vendor_specific,
            self.session.get_ble_encryption(),
        )
        await self.transport_protocol.send_message(message)

    async def send_ranging_session_setup_m3(self) -> None:
        if not isinstance(self.transport_protocol, BLEUWB):
            raise InvalidProtocolTypeError

        if self.session is None:
            raise SessionError("No Session")

        Global.logger.info("Sending ranging session setup M3 ble message")

        ran_multiplier = await self.transport_protocol.get_ran_multiplier()
        num_chaps_per_slot = await self.transport_protocol.get_num_chaps_per_slot()
        number_responder_nodes = await self.transport_protocol.get_number_responders()
        number_slots_per_round = await self.transport_protocol.get_slots_per_round()
        sync_code_index_bitmask = (
            self.transport_protocol.get_sync_code_bitmask()
            & self.received_sync_code_bitmask
        )
        hopping_conf_bitmask = self.transport_protocol.get_hopping_config_bitmask()
        mac_mode = await self.transport_protocol.get_mac_mode()
        vendor_specific = 0xFF

        message = BleMessage.create_ranging_session_setup_m3(
            ran_multiplier,
            num_chaps_per_slot,
            number_responder_nodes,
            number_slots_per_round,
            sync_code_index_bitmask,
            hopping_conf_bitmask,
            mac_mode,
            vendor_specific,
            self.session.get_ble_encryption(),
        )
        await self.transport_protocol.send_message(message)

    async def send_ranging_session_suspend_request(self) -> None:
        if not isinstance(self.transport_protocol, BLEUWB):
            raise InvalidProtocolTypeError

        Global.logger.info("Sending ranging session suspend request ble message")
        uwb_session_id = self.transport_protocol.get_uwb_session_id()

        message = BleMessage.create_ranging_session_suspend_request(
            uwb_session_id,
            self.session.get_ble_encryption(),
        )
        await self.transport_protocol.send_message(message)

    async def send_ranging_session_suspend_response(self) -> None:
        if not isinstance(self.transport_protocol, BLEUWB):
            raise InvalidProtocolTypeError

        Global.logger.info("Sending ranging session suspend response ble message")
        status = 1
        message = BleMessage.create_ranging_session_suspend_response(
            status,
            self.session.get_ble_encryption(),
        )

        await self.transport_protocol.stop_ranging()
        await self.transport_protocol.send_message(message)

    async def send_ranging_session_resume_request(self) -> None:
        if not isinstance(self.transport_protocol, BLEUWB):
            raise InvalidProtocolTypeError

        Global.logger.info("Sending ranging session resume request ble message")
        uwb_session_id = self.transport_protocol.get_uwb_session_id()

        message = BleMessage.create_ranging_session_resume_request(
            uwb_session_id,
            self.session.get_ble_encryption(),
        )
        await self.transport_protocol.send_message(message)

    async def send_ranging_session_resume_response(self) -> None:
        if not isinstance(self.transport_protocol, BLEUWB):
            raise InvalidProtocolTypeError

        Global.logger.info("Sending ranging session resume response ble message")
        sts_index0 = await self.transport_protocol.get_sts_index0()
        uwb_time0 = await self.transport_protocol.get_uwb_time0()

        message = BleMessage.create_ranging_session_resume_response(
            sts_index0,
            uwb_time0,
            self.session.get_ble_encryption(),
        )

        await self.transport_protocol.start_ranging()
        await self.transport_protocol.send_message(message)


class ReaderSession:
    """
    Contains info from a single session (with one User Device)
    """

    def __init__(
        self,
        reader_key: KeyPair,
        reader_identifier: bytes,
        vendor_extension: bytes | None = None,
        reader_system_issuer_ca: PublicKey | None = None,
    ) -> None:
        self.reader_key = reader_key
        self.reader_identifier = reader_identifier
        self.command_vendor_extension = vendor_extension
        self.response_vendor_extension: bytes | None = None
        self.encryption_expedited: EncryptionEngine | None = None
        self.encryption_stepup: EncryptionEngine | None = None
        self.ble_encryption_engine: EncryptionEngine | None = None
        self.reader_system_issuer_ca = reader_system_issuer_ca

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

    def get_reader_group_identifier_key(self) -> PublicKey:
        if self.reader_system_issuer_ca is not None:
            return self.reader_system_issuer_ca
        else:
            return self.reader_key.get_public_key()

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
        self, initiate_ap_notification: BleMessage
    ) -> None:
        self.application_type = initiate_ap_notification.application_type
        self.expedited_phase_supported_protocol_versions = (
            initiate_ap_notification.expedited_phase_supported_protocol_versions
        )
        self.maximum_command_apdu = initiate_ap_notification.maximum_command_apdu
        self.maximum_response_apdu = initiate_ap_notification.maximum_response_apdu
        self.proprietary_tlv = initiate_ap_notification.proprietary_tlv

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
        self, transaction: Transaction, authentication_policy: AuthenticationPolicy
    ) -> None:
        self.flag = bytes([transaction, authentication_policy])

    def set_response_vendor_extension(self, vendor_extension: TLV | None) -> None:
        self.response_vendor_extension = vendor_extension

    def set_credential_ephemeral_key(self, key: PublicKey) -> None:
        self.credential_ephemeral_key = key
        Global.logger.debug(
            "set access credential ephemeral key: {!r}".format(hexlify(key.as_bytes()))
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
            reader_public_key=self.get_reader_group_identifier_key(),
            reader_ephemeral_public_key=self.reader_ephemeral.get_public_key(),
            reader_identifier=self.reader_identifier,
            protocol_version=PROTOCOL_VERSION.to_bytes(2, "big"),
            transaction_identifier=self.transaction_identifier,
            flag=self.flag,
            proprietary_information=self.proprietary_tlv.to_bytes(),
        )

        derived_key = derive_key(self.shared_key, bytes(info), 160, salt)
        self.expedited_SK_reader = derived_key[0:32]
        self.expedited_SK_device = derived_key[32:64]
        self.step_up_SK = derived_key[64:96]
        self.ble_SK = derived_key[96:128]
        self.UR_SK = derived_key[128:160]
        Global.logger.debug(
            "expedited SK reader: {!r}".format(hexlify(self.expedited_SK_reader))
        )
        Global.logger.debug(
            "expedited SK device: {!r}".format(hexlify(self.expedited_SK_device))
        )
        Global.logger.debug("step up SK: {!r}".format(hexlify(self.step_up_SK)))
        Global.logger.debug("ble SK: {!r}".format(hexlify(self.ble_SK)))
        Global.logger.debug("UR SK: {!r}".format(hexlify(self.UR_SK)))

        self.create_encryption_engine_expedited()
        self.create_encryption_engine_stepup()

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
            reader_public_key=self.get_reader_group_identifier_key(),
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
        self.expedited_SK_reader = derived_key[32:64]
        self.expedited_SK_device = derived_key[64:96]
        self.ble_SK = derived_key[96:128]
        self.UR_SK = derived_key[128:160]

        Global.logger.debug("cryptogram SK: {!r}".format(hexlify(self.cryptogram_SK)))
        Global.logger.debug(
            "expedited SK reader: {!r}".format(hexlify(self.expedited_SK_reader))
        )
        Global.logger.debug(
            "expedited SK device: {!r}".format(hexlify(self.expedited_SK_device))
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
            reader_public_key=self.get_reader_group_identifier_key(),
            reader_ephemeral_public_key=self.reader_ephemeral.get_public_key(),
            reader_identifier=self.reader_identifier,
            protocol_version=PROTOCOL_VERSION.to_bytes(2, "big"),
            transaction_identifier=self.transaction_identifier,
            flag=self.flag,
            proprietary_information=self.proprietary_tlv.to_bytes(),
            credential_ephemeral_public_key=credential,
        )
        derived_key = derive_key(self.shared_key, bytes(info), 32, salt)
        return derived_key[0:32]

    def create_encryption_engine_expedited(self) -> None:
        Global.logger.debug("Creating encryption engine for expedited phase")
        self.encryption_expedited = EncryptionEngine(
            DeviceType.READER, self.expedited_SK_reader, self.expedited_SK_device
        )

    def set_ble_encryption(self, transport_protocol: TransportProtocolBase) -> None:
        if not isinstance(transport_protocol, BLEUWB):
            raise AccessProtocolError("Trying to set BLE encryption while using NFC")

        selected_version, available_versions = transport_protocol.get_ble_versions()
        self.ble_encryption_engine = get_ble_encryption(
            DeviceType.READER, self.ble_SK, selected_version, available_versions
        )

    def get_ble_encryption(self) -> EncryptionEngine | None:
        return self.ble_encryption_engine

    def encrypt_payload(self, payload: bytes) -> tuple[bytes, bytes]:
        return self.encryption.encrypt(payload)

    def create_encryption_engine_stepup(self) -> None:
        Global.logger.debug("Creating encryption engine for step-up phase")
        Global.logger.debug("deriving stepupSKReader:")
        stepup_SK_reader = derive_key(
            self.step_up_SK, "SKReader".encode("utf-8"), 32, b""
        )
        Global.logger.debug("deriving stepupSKDevice:")
        stepup_SK_device = derive_key(
            self.step_up_SK, "SKDevice".encode("utf-8"), 32, b""
        )
        self.encryption_stepup = EncryptionEngine(
            DeviceType.READER, stepup_SK_reader, stepup_SK_device
        )


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
