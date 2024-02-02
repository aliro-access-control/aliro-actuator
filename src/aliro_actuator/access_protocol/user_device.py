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

from aliro_actuator import Global
from aliro_actuator.access_protocol import Device
from aliro_actuator.access_protocol.apdu import (
    INS,
    TLV,
    Auth1Response,
    Command,
    StatusBytes,
    Transaction,
)
from aliro_actuator.access_protocol.authentication import (
    create_endpoint_authentication,
    create_reader_authentication,
)
from aliro_actuator.access_protocol.defines import (
    CSA_APPLICATION_TYPE,
    EXPEDITED_PHASE_AID,
    PROTOCOL_VERSION,
    Select,
    TransportProtocol,
)
from aliro_actuator.access_protocol.encryption import (
    DeviceType,
    EncryptionEngine,
    VerificationError,
    create_salt,
)
from aliro_actuator.access_protocol.errors import (
    AccessProtocolError,
    InvalidAIDError,
    InvalidCLAError,
    InvalidCommandError,
    InvalidParameterError,
    KeyLookupFailed,
    SessionError,
    UnexpectedCommandError,
    VersionError,
)
from aliro_actuator.access_protocol.mailbox import Mailbox
from aliro_actuator.transport_protocol import Mode, TransportProtocolBase
from aliro_actuator.trust_framework.access_credential import (
    AccessCredential,
    ReaderIdentifier,
)
from aliro_actuator.trust_framework.certificate import Certificate
from aliro_actuator.trust_framework.errors import (
    CertificateDecodingError,
    InvalidKeyError,
)
from aliro_actuator.trust_framework.key import KeyPair, PublicKey, derive_key


class UserDevice(Device):
    """
    Simulates a user device.

    Args:
        transport_protocol (TransportProtocol): The transport protocol to use.
        access_credentials (list[bytes], optional): list of access_credentials.
        Defaults to [].
        supported_versions (list[int], optional): List of supported protocol
        versions. Defaults to [PROTOCOL_VERSION].
        mailbox (int | list[tuple[bytes, int, bytes]] | None): If None, don't use
        mailbox. If int, use mailbox with this size in bytes. If list, use mailbox
        with this initial data. List should consist of OUI, type, data tuples.
    """

    def __init__(
        self,
        transport_protocol: TransportProtocol,
        transport_override: TransportProtocolBase | None = None,
        access_credentials: list[AccessCredential] = [],
        supported_versions: list[int] = [PROTOCOL_VERSION],
        mailbox: int | list[tuple[bytes, int, bytes]] | None = None,
        mailbox_read: bool = True,
        mailbox_write: bool = True,
    ):
        super().__init__(transport_protocol, transport_override)

        self.access_credentials = access_credentials
        self.supported_versions = supported_versions
        self.session: None | UserSession = None

        if mailbox is None:
            self.mailbox = None
        if isinstance(mailbox, int):
            self.mailbox = Mailbox(
                size=mailbox,
                read_permission=mailbox_read,
                write_permission=mailbox_write,
            )
        else:
            self.mailbox = Mailbox(
                initial_data=mailbox,
                read_permission=mailbox_read,
                write_permission=mailbox_write,
            )
        self.mailbox_session = MailboxSession()

    def transaction_initiation(self) -> None:
        """
        Initializes the hardware and sets up a connection to the reader.
        """
        Global.logger.info("Start Transaction Initiation")
        self.transport_protocol.initialization(Mode.CARD_EMULATION)
        self.transport_protocol.wait_for_connection()

        Global.logger.info("Transaction Initiation Done")

    def main_loop(self) -> None:
        """
        Starts a loop, where every command received is replied with an appropriate response.
        Should keep running, even when receiving invalid commands.

        Raises:
            SessionError: When starting a new session failed.
            NotImplementedError: When a command which is not implemented is received.
        """
        if self.session is None:
            self.start_new_session()
        if self.session is None:
            raise SessionError("starting session failed")

        while True:
            command = self.wait_for_command(encryption=self.session.encryption)
            try:
                match command.ins:
                    case INS.SELECT:
                        self.handle_select(command)
                    case INS.AUTH0:
                        self.handle_auth0(command)
                    case INS.AUTH1:
                        self.handle_auth1(command)
                    case INS.LOAD_CERT:
                        self.handle_load_cert(command)
                    case INS.CONTROL_FLOW:
                        self.handle_control_flow(command)
                    case INS.EXCHANGE:
                        self.handle_exchange(command)
                    case _:
                        raise NotImplementedError(
                            "command: {} not implemented".format(command.ins)
                        )
            except (InvalidKeyError, InvalidAIDError):
                # main loop should continue even when commands are not valid
                pass
            except VerificationError:
                self.session.update_state(UserSessionState.SELECT_DONE)
                self.mailbox_session.stop()

    def start_new_session(self, ephemeral_key: KeyPair | None = None) -> None:
        """
        Start a new user session. Must be done before using handle commands.
        This sessions stores all information received from commands.
        Start a new session to delete all received info and start over.

        Args:
            ephemeral_key (KeyPair | None, optional): ephemeral reader key used for the
            session. Randomly generated if None. Defaults to None.
        """
        Global.logger.info("Starting new session")
        self.session = UserSession(self.supported_versions)

        self.session.generate_ephemeral_key(ephemeral_key)

    def handle_select(self, select_command: Command) -> None:
        """
        Parse a select command and send the appropriate response.

        Args:
            select_command (Command): The command to respond to.

        Raises:
            SessionError: Raised if no session is found.
            InvalidAIDError: Raised when the AID is invalid.
        """
        if select_command.ins != INS.SELECT:
            raise AccessProtocolError(
                "Tried to handle Select command, "
                "but received command is not a select command"
            )

        if self.session is None:
            raise SessionError("No Session")

        Global.logger.info("Received Select Command")
        if select_command.aid != EXPEDITED_PHASE_AID:
            Global.logger.warning("Invalid AID")
            self.response_error(StatusBytes.FILE_OR_APP_NOT_FOUND)
            raise InvalidAIDError(select_command.to_bytes(), select_command.aid)

        self.session.update_state(UserSessionState.SELECT_DONE)

        Global.logger.info("Sending Select Response")
        self.response_select(
            select_command.aid,
            CSA_APPLICATION_TYPE,
            self.supported_versions,
        )

    def handle_auth0(self, auth0_command: Command) -> None:
        """
        Parse a auth0 command and send the appropriate response.

        Args:
            auth0_command (Command): The command to respond to.

        Raises:
            SessionError: Raised when the session is missing or in an invalid state.
            VersionError: Raised when the protocol version is not supported.
            NotImplementedError:
        """
        if auth0_command.ins != INS.AUTH0:
            raise AccessProtocolError(
                "Tried to handle auth0 command, "
                "but received command is not a auth0 command"
            )

        if self.session is None:
            raise SessionError("No Session")
        if not self.session.state_valid(UserSessionState.SELECT_DONE):
            self.response_error(StatusBytes.INVALID_INSTRUCTION)
            raise SessionError(
                "unexpected state for auth0 command: {}".format(self.session.state)
            )

        Global.logger.info("Received AUTH0 Command")
        if (
            auth0_command.expedited_phase_protocol_version
            not in self.supported_versions
        ):
            self.response_error(StatusBytes.CONDITIONS_OF_USE_NOT_SATISFIED)
            raise VersionError

        try:
            self.session.set_auth0_data(auth0_command)
        except InvalidKeyError:
            AccessProtocolError("Reader ephemeral key is invalid")

        for access_credential in self.access_credentials:
            if access_credential.has_identifier(self.session.reader_group_identifier):
                self.session.set_access_credential(access_credential)

        if self.session.get_transaction_type() == Transaction.STANDARD:
            Global.logger.info("Standard transaction requested")
            self.session.update_state(UserSessionState.AUTH0_STD_DONE)
            Global.logger.info("Sending AUTH0 Response")
            self.response_auth0(self.session.get_credential_epubkey().as_bytes())
        if self.session.get_transaction_type() == Transaction.FAST:
            Global.logger.info("Fast transaction requested")
            raise NotImplementedError

    def handle_load_cert(self, load_cert_command: Command) -> None:
        """
        Parse a load cert command and send the appropriate response.

        Args:
            load_cert_command (Command): The command to respond to.

        Raises:
            SessionError: Raised when the session is missing or in an invalid state.
            KeyLookupFailed: When the reader public key cannot be found.
        """
        if load_cert_command.ins != INS.LOAD_CERT:
            raise AccessProtocolError(
                "Tried to handle load_cert command, "
                "but received command is not a load_cert command"
            )

        if self.session is None:
            raise SessionError("No Session")
        if not self.session.state_valid(
            [UserSessionState.AUTH0_FAST_DONE, UserSessionState.AUTH0_STD_DONE]
        ):
            self.response_error(StatusBytes.INVALID_INSTRUCTION)
            raise SessionError(
                "unexpected state for auth0 command: {}".format(self.session.state)
            )

        Global.logger.info("Received LOAD CERT Command")
        try:
            reader_public_key = self.session.get_access_credential_reader_public_key(
                self.access_credentials
            )
            if reader_public_key is None:
                raise KeyLookupFailed
            self.session.set_cert_and_verify(
                load_cert_command.reader_cert, reader_public_key
            )
        except CertificateDecodingError:
            self.response_error(StatusBytes.GENERIC_ERROR)
            return
        self.response_load_cert()

    def handle_auth1(self, auth1_command: Command) -> None:
        """
        Parse a auth1 command and send the appropriate response.

        Args:
            auth1_command (Command): The command to respond to.

        Raises:
            SessionError: Raised when the session is missing or in an invalid state.
            KeyLookupFailed: When the reader public key cannot be found.
            AccessProtocolError: Raised if the response has invalid data.
        """
        if auth1_command.ins != INS.AUTH1:
            raise AccessProtocolError(
                "Tried to handle auth1 command, "
                "but received command is not a auth1 command"
            )

        if self.session is None:
            raise SessionError("No Session")
        if not self.session.state_valid(
            [UserSessionState.AUTH0_FAST_DONE, UserSessionState.AUTH0_STD_DONE]
        ):
            self.response_error(StatusBytes.INVALID_INSTRUCTION)
            raise SessionError(
                "unexpected state for auth0 command: {}".format(self.session.state)
            )

        Global.logger.info("Received AUTH1 Command")
        if auth1_command.certificate_data is not None:
            Global.logger.info("AUTH1 Command contains certificate")
            try:
                reader_public_key = (
                    self.session.get_access_credential_reader_public_key(
                        self.access_credentials
                    )
                )
                if reader_public_key is None:
                    raise KeyLookupFailed
                self.session.set_cert_and_verify(
                    auth1_command.certificate_data, reader_public_key
                )
            except CertificateDecodingError:
                Global.logger.error("Error decoding certificate")
                self.response_error(StatusBytes.GENERIC_ERROR)
                return

        self.session.set_reader_public_key(self.access_credentials)

        data = create_reader_authentication(
            self.session.reader_identifier,
            self.session.get_credential_epubkey(),
            self.session.reader_epubk,
            self.session.transaction_identifier,
        )
        Global.logger.debug(
            "verifying with signature: {!r}".format(
                hexlify(auth1_command.reader_signature)
            )
        )
        verified = self.session.get_reader_public_key().verify(
            data.to_bytes(), auth1_command.reader_signature
        )
        if not verified:
            self.response_error(StatusBytes.GENERIC_ERROR)
            raise AccessProtocolError("reader authentication data not verified")
        Global.logger.info("reader authentication data verified successfully")

        Global.logger.info("creating shared keys")
        self.session.set_shared_key()
        self.session.derive_key_volatile(self.transport_protocol_type)
        self.session.derive_key_persistent(self.transport_protocol_type)

        Global.logger.info("creating endpoint authentication")
        data = create_endpoint_authentication(
            self.session.reader_identifier,
            self.session.get_credential_epubkey(),
            self.session.reader_epubk,
            self.session.transaction_identifier,
        )
        Global.logger.debug(
            "created endpoint authentication_data: {!r}".format(
                hexlify(data.to_bytes())
            )
        )
        signature = self.session.access_credential.sign(data.to_bytes())
        Global.logger.debug(
            "created endpoint authentication_data signature: {!r}".format(
                hexlify(signature)
            )
        )

        if self.session.encryption is None:
            raise AccessProtocolError("no encryption engine found")

        Global.logger.info("sending AUTH1 response")
        mailbox_read = False
        mailbox_write = False
        data_in_mailbox = False
        if self.mailbox is not None:
            mailbox_read = self.mailbox.read_permission
            mailbox_write = self.mailbox.write_permission
            data_in_mailbox = self.mailbox.data_is_set()
        self.response_auth1(
            self.session.access_credential.key_slot,
            self.session.access_credential.get_credential_public_key().as_bytes(),
            auth1_command.expected_response,
            signature,
            self.session.encryption,
            0x9000,
            data_in_mailbox=data_in_mailbox,
            read_mailbox=mailbox_read,
            write_mailbox=mailbox_write,
        )

    def handle_exchange(self, exchange_command: Command) -> None:
        """
        Parse an exchange command and send the appropriate response.

        Args:
            exchange_command (Command): The command to respond to.

        Raises:
            SessionError: Raised when the session is missing or in an invalid state.
            AccessProtocolError: Raised if the response has invalid data.
        """
        if exchange_command.ins != INS.EXCHANGE:
            raise AccessProtocolError(
                "Tried to handle exchange command, "
                "but received command is not a exchange command"
            )

        if self.session is None:
            raise SessionError("No Session")
        if self.session.encryption is None:
            raise SessionError("No encryption engine")
        if not self.session.state_valid(
            [
                UserSessionState.AUTH0_FAST_DONE,
                UserSessionState.AUTH1_DONE,
                UserSessionState.EXCHANGE_DONE,
            ]
        ):
            self.response_error(StatusBytes.INVALID_INSTRUCTION)
            raise SessionError(
                "unexpected state for auth0 command: {}".format(self.session.state)
            )

        if not self.session.encryption.check_counters_valid():
            # End current session
            self.start_new_session()
            self.session.update_state(UserSessionState.SELECT_DONE)
            self.response_error(StatusBytes.INVALID_INSTRUCTION)
            return

        self.session.update_state(UserSessionState.EXCHANGE_DONE)

        if (
            len(exchange_command.read_requests)
            + len(exchange_command.write_requests)
            + len(exchange_command.set_requests)
            > 0
        ):
            if self.mailbox is None:
                self.return_exchange_error_and_close_channel()
                return

            for read in exchange_command.read_requests:
                if read is None:
                    raise AccessProtocolError
                if not self.mailbox.check_boundaries(
                    int.from_bytes(read[0:2], "big"), int.from_bytes(read[2:4], "big")
                ):
                    self.return_exchange_error_and_close_channel()
                    return

            for write in exchange_command.write_requests:
                if write is None:
                    raise AccessProtocolError
                if not self.mailbox.check_boundaries(
                    int.from_bytes(write[0:2], "big"), len(write) - 2
                ):
                    self.return_exchange_error_and_close_channel()
                    return

            for set in exchange_command.set_requests:
                if set is None:
                    raise AccessProtocolError
                if not self.mailbox.check_boundaries(
                    int.from_bytes(set[0:2], "big"), int.from_bytes(set[2:4], "big")
                ):
                    self.return_exchange_error_and_close_channel()
                    return

        # handle notifications
        if exchange_command.notify is not None:
            errors = exchange_command.notify.get_all_bytes_of_tag(0xC1)
            for error in errors:
                if error is None:
                    raise AccessProtocolError
                Global.logger.info(
                    "received error notification: {!r}".format(hexlify(error))
                )

        # handle reads
        read_data: list[tuple[int, bytes]] = []
        if self.mailbox is not None:
            for read in exchange_command.read_requests:
                if read is None:
                    raise AccessProtocolError
                mailbox_read = self.mailbox.read(
                    int.from_bytes(read[:2], "big"),
                    int.from_bytes(read[2:4], "big"),
                )
                read_data.append((len(mailbox_read), mailbox_read))

        # Handle write/sets
        if self.mailbox is not None:
            if exchange_command.atomic_session:
                self.mailbox_session.start()

            if self.mailbox_session.is_started():
                for set in exchange_command.set_requests:
                    self.mailbox_session.add_set(set)
                for write in exchange_command.write_requests:
                    self.mailbox_session.add_write(write)
                if not exchange_command.atomic_session:
                    self.mailbox_session.execute_commands(self.mailbox)
                    self.mailbox_session.stop()
            else:
                # no started sessions, so only execute this command
                mailbox_session = MailboxSession()
                for set in exchange_command.set_requests:
                    mailbox_session.add_set(set)
                for write in exchange_command.write_requests:
                    mailbox_session.add_write(write)
                if not exchange_command.atomic_session:
                    mailbox_session.execute_commands(self.mailbox)

        # generate payload
        exchange_payload = bytearray()
        for read_command in read_data:
            exchange_payload.extend(read_command[0].to_bytes(1, "big"))
            exchange_payload.extend(read_command[1])
        exchange_payload.extend(bytes([0x02, 0x00, 0x00]))

        self.response_exchange(exchange_payload, self.session.encryption)

    def return_exchange_error_and_close_channel(self) -> None:
        """
        Return an exchange error and close the channel.
        Used when an exchange fails.

        Raises:
            SessionError: Raised if no session is found.
            AccessProtocolError: Raised if no encryption engine is found.
        """
        if self.session is None:
            raise SessionError("No Session")
        if self.session.encryption is None:
            raise AccessProtocolError("no encryption engine found")

        exchange_payload = bytes.fromhex("0002FFFF")
        self.response_exchange(exchange_payload, self.session.encryption)

    def handle_control_flow(self, control_flow_command: Command) -> None:
        """
        Parse an control flow command and send the appropriate response.

        Args:
            control_flow_command (Command): The command to respond to.

        Raises:
            SessionError: Raised when the session is missing or in an invalid state.
        """
        if control_flow_command.ins != INS.CONTROL_FLOW:
            raise AccessProtocolError(
                "Tried to handle control_flow command, "
                "but received command is not a control_flow command"
            )

        if self.session is None:
            raise SessionError("No Session")

        Global.logger.info("Received CONTROL FLOW Command")
        if control_flow_command.s1 == 0x00:
            Global.logger.info("transaction finished with failure")
        elif control_flow_command.s2 == 0x02:
            Global.logger.info("transaction finished with success")

        # End current session
        self.start_new_session()
        self.session.update_state(UserSessionState.SELECT_DONE)

        self.response_control_flow()

    def wait_for_command(
        self,
        expected_command: INS | list[INS] | None = None,
        encryption: EncryptionEngine | None = None,
    ) -> Command:
        """
        Waits until a command is received, and parses the command.

        Args:
            expected_command (INS | list[INS] | None, optional): INS or list of INS with
            expected commands. raises UnexpectedCommandError if another command is received. Defaults to None.
            encryption (EncryptionEngine | None, optional): Used for decrypting messages.
            Not required for every command. Defaults to None.

        Raises:
            InvalidCLAError: Raised when the received command has an invalid CLA.
            InvalidParameterError: Raised when the received command has an invalid Paramenter (P1 or P2).
            InvalidCommandError: Raised when the received command is invalid.
            VerificationError: Raised when the verification of an AES decryption fails.
            UnexpectedCommandError: when the command is not in expected_command.

        Returns:
            Command: the received command.
        """
        if isinstance(expected_command, INS):
            expected_command = [expected_command]

        Global.logger.info("Waiting for command")
        command_str = self.transport_protocol.get_message()
        Global.logger.info("Received command")
        try:
            command = self.apdu.parse_command(command_str, encryption)
        except InvalidCLAError as error:
            self.response_error(StatusBytes.FUNCTIONS_IN_CLA_NOT_SUPPORTED)
            raise error
        except InvalidParameterError as error:
            self.response_error(StatusBytes.INCORRECT_P1_P2)
            raise error
        except InvalidCommandError as error:
            self.response_error(StatusBytes.COMMAND_NOT_COMPLIANT)
            raise error
        except VerificationError as error:
            self.response_error(StatusBytes.INCORRECT_SECURE_MESSAGING_DOS)
            raise error

        if expected_command is not None and command.ins not in expected_command:
            raise UnexpectedCommandError
        return command

    def response_auth0(
        self, credential_epubk: bytes, cryptogram: bytes | None = None
    ) -> None:
        """
        Create and send an auth0 response.

        Args:
            credential_epubk (bytes): Credential Ephemeral public key.
            cryptogram (bytes | None, optional): authentication cryptogram. Defaults to None.
        """
        auth0_response = self.apdu.create_auth0_response(
            credential_epubk, StatusBytes.SUCCESS, cryptogram
        )
        self.transport_protocol.send_message(auth0_response.to_bytes())

    def response_auth1(
        self,
        key_slot: bytes | None,
        credential_public_key: bytes | None,
        expected_response: Auth1Response,
        signature: bytes,
        encryption: EncryptionEngine,
        status: int = StatusBytes.SUCCESS,
        private_mailbox_data: bytes | None = None,
        access_doc_retrieve: bool = False,
        revocation_doc_retrieve: bool = False,
        step_up_aid_required: bool = False,
        data_in_mailbox: bool = False,
        read_mailbox: bool = False,
        write_mailbox: bool = False,
        send_issuer_backend: bool = False,
        send_bound_app: bool = False,
        update_doc: bool = False,
        credential_signed_timestamp: bytes | None = None,
        revocation_signed_timestamp: bytes | None = None,
    ) -> None:
        """
        Create and send an auth1 response.

        Args:
            key_slot (bytes | None): First 8 byes of the keyIdentifier.
            credential_public_key (bytes | None): Credential long term public key.
            expected_response (Auth1Response): expected response (keyslot or credential public key)
            signature (bytes): Endpoint authentication signature.
            encryption (EncryptionEngine): Encryption engine to encrypt the response.
            status (int, optional): response status. Defaults to StatusBytes.SUCCESS.
            private_mailbox_data (bytes | None, optional): Defaults to None.
            access_doc_retrieve (bool, optional): Part of signaling bitmap. Defaults to False.
            revocation_doc_retrieve (bool, optional): Part of signaling bitmap. Defaults to False.
            step_up_aid_required (bool, optional): Part of signaling bitmap. Defaults to False.
            data_in_mailbox (bool, optional): Part of signaling bitmap. Defaults to False.
            read_mailbox (bool, optional): Part of signaling bitmap. Defaults to False.
            write_mailbox (bool, optional): Part of signaling bitmap. Defaults to False.
            send_issuer_backend (bool, optional): Part of signaling bitmap. Defaults to False.
            send_bound_app (bool, optional): Part of signaling bitmap. Defaults to False.
            update_doc (bool, optional): Part of signaling bitmap. Defaults to False.
            credential_signed_timestamp (bytes | None, optional): Defaults to None.
            revocation_signed_timestamp (bytes | None, optional): Defaults to None.
        """
        auth1_response = self.apdu.create_auth1_response(
            key_slot,
            credential_public_key,
            expected_response,
            signature,
            encryption,
            status,
            private_mailbox_data,
            access_doc_retrieve,
            revocation_doc_retrieve,
            step_up_aid_required,
            data_in_mailbox,
            read_mailbox,
            write_mailbox,
            send_issuer_backend,
            send_bound_app,
            update_doc,
            credential_signed_timestamp,
            revocation_signed_timestamp,
        )
        self.transport_protocol.send_message(auth1_response.to_bytes())

    def response_select(
        self,
        aid: bytes,
        type: int,
        protocol_versions: list[int],
        maximum_command_apdu: int | None = None,
        maximum_response_apdu: int | None = None,
        vendor_specific_tlv: TLV | None = None,
    ) -> None:
        """
        Create and send a select response.

        Args:
            aid (bytes): AID
            type (int): Application type (table 10-4)
            protocol_versions (list[int]): Expedited phase supported protocol versions.
            maximum_command_apdu (int | None, optional): Defaults to None.
            maximum_response_apdu (int | None, optional): Defaults to None.
            vendor_specific_tlv (TLV | None, optional): Defaults to None.
        """
        select_response = self.apdu.create_select_response(
            aid,
            type,
            protocol_versions,
            status=StatusBytes.SUCCESS,
            maximum_command_apdu=maximum_command_apdu,
            maximum_response_apdu=maximum_response_apdu,
            vendor_specific_tlv=vendor_specific_tlv,
        )
        self.transport_protocol.send_message(select_response.to_bytes())

    def response_envelope(self) -> None:
        raise NotImplementedError

    def response_get_response(self) -> None:
        raise NotImplementedError

    def response_load_cert(self) -> None:
        """
        Create and send a load cert response.
        """
        load_cert_response = self.apdu.create_load_cert_response(StatusBytes.SUCCESS)
        self.transport_protocol.send_message(load_cert_response.to_bytes())

    def response_exchange(
        self,
        payload: bytes,
        encryption: EncryptionEngine,
    ) -> None:
        """
        Create and send a exchange response.

        Args:
            payload (bytes): exchange response payload.
            encryption (EncryptionEngine): encryption engine to encrypt the payload.
        """
        exchange_response = self.apdu.create_exchange_response(
            payload, encryption, StatusBytes.SUCCESS
        )
        self.transport_protocol.send_message(exchange_response.to_bytes())

    def response_control_flow(self) -> None:
        """
        Create and send a control flow response.
        """
        control_flow_response = self.apdu.create_control_flow_response(
            StatusBytes.SUCCESS
        )
        self.transport_protocol.send_message(control_flow_response.to_bytes())

    def response_error(self, status_bytes: int) -> None:
        """
        Create and send an error response.
        """

        response = self.apdu.create_error_response(status_bytes)
        self.transport_protocol.send_message(response.to_bytes())


class UserSessionState(Enum):
    SESSION_START = 1
    SELECT_DONE = 2
    AUTH0_STD_DONE = 3
    AUTH0_FAST_DONE = 4
    AUTH1_DONE = 5
    EXCHANGE_DONE = 6


class UserSession:
    """
    Contains info from a single session (with one Reader Device)
    """

    def __init__(self, supported_version: list[int]) -> None:
        self.state = UserSessionState.SESSION_START
        self.supported_versions = supported_version
        self.encryption: EncryptionEngine | None = None

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

    def update_state(self, state: UserSessionState) -> None:
        self.state = state

    def state_valid(self, state: list[UserSessionState] | UserSessionState) -> bool:
        if isinstance(state, UserSessionState):
            state = [state]
        if self.state in state:
            return True
        return False

    def set_auth0_data(
        self,
        auth0_command: Command,
    ) -> None:
        self.command_parameters = auth0_command.command_parameters
        self.transaction_code = auth0_command.transaction_code
        self.expedited_phase_protocol_version = (
            auth0_command.expedited_phase_protocol_version
        )
        self.reader_epubk = PublicKey(auth0_command.reader_epubk)
        self.transaction_identifier = auth0_command.transaction_identifier
        self.reader_identifier = auth0_command.reader_identifier
        self.vendor_specific_extension = auth0_command.vendor_specific_extension

    def set_access_credential(self, access_credential: AccessCredential) -> None:
        self.access_credential = access_credential

    def generate_ephemeral_key(self, ephemeral_key: KeyPair | None = None) -> None:
        if ephemeral_key is None:
            self.credential_ephemeral = KeyPair()
        else:
            self.credential_ephemeral = ephemeral_key

    def get_credential_epubkey(self) -> PublicKey:
        return self.credential_ephemeral.get_public_key()

    def get_transaction_type(self) -> Transaction:
        if self.command_parameters == Transaction.FAST:
            return Transaction.FAST
        elif self.command_parameters == Transaction.STANDARD:
            return Transaction.STANDARD
        else:
            raise IndexError

    def set_shared_key(self) -> None:
        self.shared_key = (
            self.credential_ephemeral.get_private_key().compute_shared_key(
                self.reader_epubk, self.transaction_identifier
            )
        )

    def derive_key_volatile(self, transport_protocol: TransportProtocol) -> None:
        info = bytearray(
            self.credential_ephemeral.get_public_key().get_x().to_bytes(32, "big")
        )
        if self.vendor_specific_extension is not None:
            info.extend(self.vendor_specific_extension)
        salt = create_salt(
            transport_protocol=transport_protocol,
            word=b"Volatile****",
            reader_public_key=self.access_credential.get_reader_public_key(),
            reader_ephemeral_public_key=self.reader_epubk,
            reader_identifier=self.reader_identifier,
            protocol_version=self.expedited_phase_protocol_version.to_bytes(2, "big"),
            transaction_identifier=self.transaction_identifier,
            flag=bytes([self.command_parameters, self.transaction_code]),
            application_type=CSA_APPLICATION_TYPE,
            expedited_phase_supported_protocol_versions=self.supported_versions,
        )
        derived_key = derive_key(self.shared_key, bytes(info), 160, salt)
        self.exchange_SK_reader = derived_key[0:32]
        self.exchange_SK_device = derived_key[32:64]
        self.step_up_SK = derived_key[64:96]
        self.ble_SK = derived_key[96:128]
        self.UR_SK = derived_key[128:160]

        self.encryption = EncryptionEngine(
            DeviceType.USER, self.exchange_SK_reader, self.exchange_SK_device
        )

    def derive_key_persistent(self, transport_protocol: TransportProtocol) -> None:
        info = bytearray(
            self.credential_ephemeral.get_public_key().get_x().to_bytes(32, "big")
        )
        if self.vendor_specific_extension is not None:
            info.extend(self.vendor_specific_extension)
        salt = create_salt(
            transport_protocol=transport_protocol,
            word=b"Persistent**",
            reader_public_key=self.access_credential.get_reader_public_key(),
            reader_ephemeral_public_key=self.reader_epubk,
            reader_identifier=self.reader_identifier,
            protocol_version=self.expedited_phase_protocol_version.to_bytes(2, "big"),
            transaction_identifier=self.transaction_identifier,
            flag=bytes([self.command_parameters, self.transaction_code]),
            application_type=CSA_APPLICATION_TYPE,
            expedited_phase_supported_protocol_versions=self.supported_versions,
            credential_ephemeral_public_key=self.access_credential.get_credential_public_key(),
        )
        derived_key = derive_key(self.shared_key, bytes(info), 32, salt)
        self.k_persistent = derived_key[0:32]

    def set_cert_and_verify(
        self, compressed_cert: bytes, public_key: PublicKey
    ) -> bool:
        # TODO set data
        self.cert = Certificate.decode_compressed(compressed_cert)
        data = b""
        return self.cert.verify(public_key, data)

    def get_access_credential_reader_public_key(
        self, access_credentials: list[AccessCredential]
    ) -> PublicKey | None:
        for access_credential in access_credentials:
            if access_credential.has_identifier(self.reader_group_identifier):
                return access_credential.get_reader_public_key()
        return None

    def get_reader_public_key(self) -> PublicKey:
        return self.reader_public_key

    def set_reader_public_key(self, access_credentials: list[AccessCredential]) -> None:
        if hasattr(self, "cert"):
            self.reader_public_key = self.cert.get_public_key()
            Global.logger.info(
                "set reader public key from certificate: {!r}".format(
                    hexlify(self.reader_public_key.as_bytes())
                )
            )
            return
        for access_credential in access_credentials:
            if access_credential.has_identifier(self.reader_group_identifier):
                self.reader_public_key = access_credential.get_reader_public_key()
                Global.logger.info(
                    "set reader public key from access_credentials: {!r}".format(
                        hexlify(self.reader_public_key.as_bytes())
                    )
                )
                return
        else:
            raise AccessProtocolError("No reader public key found")


class MailboxSession:
    class Command(Enum):
        SET = 0
        WRITE = 1

    def __init__(self) -> None:
        self.commands: list[tuple[MailboxSession.Command, bytes]] = []
        self.started = False

    def start(self) -> None:
        self.started = True

    def stop(self) -> None:
        self.commands = []
        self.started = False

    def is_started(self) -> bool:
        return self.started

    def add_write(self, data: bytes | None) -> None:
        if data is None:
            raise AccessProtocolError
        command = (MailboxSession.Command.WRITE, data)
        self.commands.append(command)

    def add_set(self, data: bytes | None) -> None:
        if data is None:
            raise AccessProtocolError
        command = (MailboxSession.Command.SET, data)
        self.commands.append(command)

    def execute_commands(self, mailbox: Mailbox) -> None:
        for command in self.commands:
            if command[0] == MailboxSession.Command.WRITE:
                offset = int.from_bytes(command[1][:2], "big")
                mailbox.write(offset, command[1][2:])
            if command[0] == MailboxSession.Command.SET:
                offset = int.from_bytes(command[1][:2], "big")
                length = int.from_bytes(command[1][2:4], "big")
                mailbox.set(offset, length, command[1][4])
