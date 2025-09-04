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
from enum import Enum, IntEnum

from os import urandom
import cbor2

import ucitool.base_uci.helpers.uci_helper as uci

from aliro_actuator import Global
from aliro_actuator.access_document.access_document import AccessDocument
from aliro_actuator.access_document.revocation_document import RevocationDocument
from aliro_actuator.access_protocol.apdu import (
    INS,
    TLV,
    APDUMessage,
    Auth1Response,
    Command,
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
    Auth0,
    Select,
    TransportProtocol,
)
from aliro_actuator.access_protocol.device import Device
from aliro_actuator.access_protocol.encryption import (
    DeviceType,
    EncryptionEngine,
    VerificationError,
    compute_cryptogram,
    create_proprietary_information,
    create_salt,
)
from aliro_actuator.access_protocol.errors import (
    AccessProtocolError,
    InvalidAIDError,
    InvalidCLAError,
    InvalidCommandError,
    InvalidHoppingConfig,
    InvalidINSError,
    InvalidParameterError,
    InvalidPulseShapeCombo,
    InvalidSyncCodeIndex,
    InvalidUWBSessionId,
    SessionError,
    UnexpectedBLEMessageError,
    UnexpectedCommandError,
    VersionError,
)
from aliro_actuator.access_protocol.mailbox import Mailbox
from aliro_actuator.hw_driver.murata_driver.uwb_driver import (
    Channel,
    HoppingConfig,
    UCIHoppingConfig,
    pulse_shape_combo,
)
from aliro_actuator.transport_protocol import Mode, TransportProtocolBase
from aliro_actuator.transport_protocol.ble_encryption import get_ble_encryption
from aliro_actuator.transport_protocol.ble_message_format import (
    AP_ID,
    BleMessage,
    Event_AttributeID,
    Notification_ID,
    ProtocolType,
    UWB_RangingService_ID,
    GeneralError_Values,
    RangingMessage_AttributeID,
)
from aliro_actuator.transport_protocol.ble_uwb import BLEUWB
from aliro_actuator.transport_protocol.errors import (
    InvalidProtocolTypeError,
    NoDeviceConnectedError,
    UnexpectedMessageTypeError,
    BLEMessageError,
    TimeoutError,
)
from aliro_actuator.trust_framework.access_credential import AccessCredential
from aliro_actuator.trust_framework.certificate import Certificate
from aliro_actuator.trust_framework.errors import (
    CertificateDecodingError,
    InvalidKeyError,
    KeyLookupFailed,
)
from aliro_actuator.trust_framework.key import KeyPair, PublicKey, derive_key
from aliro_actuator.trust_framework.reader_identifier import ReaderIdentifier

class UserMode(Enum):
    TEST = 0  # Every error raises an Exception
    USER = 1  # Strictly follows spec, may ignore errors if so noted in the spec
    
class RkeAction(IntEnum):
    SECURE = 0
    UNSECURE = 1


class UserStorage:
    """
    Cross-session storage for Expedited Fast cached data
    """

    def __init__(self) -> None:
        self.kpersistent_map: dict[bytes, bytes] = {}

    def add_kpersistent(self, kpersistent: bytes, reader_group_sub_id: bytes) -> None:
        Global.logger.info(
            "adding Kpersistent to storage: {!r}".format(hexlify(kpersistent))
        )
        Global.logger.info(
            "with reader sub id: {!r}".format(hexlify(reader_group_sub_id))
        )
        self.kpersistent_map[reader_group_sub_id] = kpersistent

    def find_kpersistent(self, reader_group_sub_id: bytes) -> bytes | None:
        if reader_group_sub_id not in self.kpersistent_map:
            return None
        return self.kpersistent_map[reader_group_sub_id]

    def remove_kpersistent(self, reader_group_sub_id: bytes) -> None:
        self.kpersistent_map.pop(reader_group_sub_id)

    def clear_kpersistent(self) -> None:
        self.kpersistent_map = {}


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
        access_document: bytes | None = None,
        revocation_document: bytes | None = None,
        mailbox: int | list[tuple[bytes, int, bytes]] | None = None,
        mailbox_read: bool = True,
        mailbox_write: bool = True,
        vendor_extension: bytes | None = None,
        fast_transaction_implemented: bool = True,
        user_device_storage: UserStorage | None = None,
        step_up_aid_required: bool = False,
        access_document_updatable: bool = False,
        group_resolving_key: bytes = 16 * bytes.fromhex("00"),
        ephemeral_key_list: list[KeyPair] | None = None,
        mode: UserMode = UserMode.TEST,
        support_step_up_notify: bool = True,
        support_step_up_update_doc: bool = True,
        timeout: float | None = None,
        enable_uwb: bool = True,
    ):
        super().__init__(transport_protocol, transport_override)

        self.access_credentials = access_credentials
        self.supported_versions = supported_versions
        self.session: None | UserSession = None
        self.access_document = access_document
        self.revocation_document = revocation_document
        self.access_document_updatable = access_document_updatable

        if user_device_storage is None:
            user_device_storage = UserStorage()
        self.storage = user_device_storage

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

        self.vendor_extension = vendor_extension

        self.fast_transaction_implemented = fast_transaction_implemented
        self.step_up_aid_required = step_up_aid_required
        self.has_issuer_backend = False
        self.has_bound_application = False

        self.group_resolving_key = group_resolving_key

        self.ephemeral_key_list = ephemeral_key_list

        self.mode = mode

        self.support_step_up_notify = support_step_up_notify
        self.support_step_up_update_doc = support_step_up_update_doc
        
        self.timeout = timeout
        self._timer = None
        self.enable_uwb = enable_uwb

    async def handle_timeout(self):
        # Send general error event
        Global.logger.info("Command timed out")
        await self.send_event(Event_AttributeID.GENERAL_ERROR, GeneralError_Values.UNKNOWN_ERROR)
        await self.transaction_termination()

    async def transaction_initiation(self, rke: bool = False) -> None:
        """
        Initializes the hardware and sets up a connection to the reader.
        """
        Global.logger.info("Start Transaction Initiation")
        await self.setup_connection()

        self.start_new_session()
        if (
            self.transport_protocol_type == TransportProtocol.BLE_UWB
            or self.transport_protocol_type == TransportProtocol.SOCKET_BLE
        ):
            await self.send_initiate_access_protocol_notification(rke=rke)
        else:
            command = await self.wait_for_command()
            await self.handle_select(command)

        Global.logger.info("Transaction Initiation Done")

    async def transaction_termination(self) -> None:
        """
        terminates the connection to the reader.
        """
        Global.logger.info("Terminating transaction")
        self.end_session()
        await self.transport_protocol.disconnect()

    async def setup_connection(self) -> None:
        """
        Setup up the connection to the reader device.
        """
        Global.logger.info("Setting up connection")
        reader_group_list = []
        for access_credential in self.access_credentials:
            reader_group_list.extend(access_credential.get_all_reader_id())
        await self.transport_protocol.initialization(
            Mode.USER_DEVICE,
            group_resolving_key=self.group_resolving_key,
            reader_group_identifier_list=reader_group_list,
            timeout=self.timeout,
            enable_uwb=self.enable_uwb
        )
        await self.transport_protocol.wait_for_connection()
        Global.logger.info("Connection established")

    def get_signaling_bitmap(self) -> bytes:
        out = 0
        if self.access_document is not None:
            out |= 1 << 0
        if self.revocation_document is not None:
            out |= 1 << 1
        if self.step_up_aid_required:
            out |= 1 << 2
        if self.mailbox is not None and self.mailbox.data_is_set():
            out |= 1 << 3
        if self.mailbox is not None and self.mailbox.read_permission:
            out |= 1 << 4
        if self.mailbox is not None and self.mailbox.write_permission:
            out |= 1 << 5
        if self.has_issuer_backend:
            out |= 1 << 6
        if self.has_bound_application:
            out |= 1 << 7
        if self.access_document is not None and self.access_document_updatable:
            out |= 1 << 9
        if self.mailbox is not None and self.mailbox.step_up_permission:
            out |= 1 << 10
        if self.support_step_up_notify:
            out |= 1 << 11
        if self.support_step_up_update_doc:
            out |= 1 << 12
        return out.to_bytes(2, "big")

    async def main_loop(self) -> None:
        """
        Starts a loop, where every command received is replied with an appropriate response.
        Should keep running, even when receiving invalid commands.

        Raises:
            SessionError: When starting a new session failed.
            NotImplementedError: When a command which is not implemented is received.
        """

        while True:
            await self.transaction_initiation()
            while True:
                try:
                    if self.session is None:
                        raise SessionError("starting session failed")
                    message = await self.wait_for_message()
                    if isinstance(message, BleMessage) and (message.header == ProtocolType.NOTIFICATION) and (
                        message.id == Notification_ID.EVENT) and (
                        message.payload is not None and message.payload[0] == Event_AttributeID.BUSY):
                        # Received busy event
                        if True == self.transport_protocol.was_timer_started():
                            continue
                except (InvalidAIDError, InvalidINSError) as error:
                    Global.logger.info(f"Caught exception: {error}")
                    # retry wait for message
                    continue
                except (InvalidCommandError, VerificationError):
                    await self.failure_process(StatusBytes.COMMAND_NOT_COMPLIANT)
                    break
                except NoDeviceConnectedError:
                    # try to reconnect in outer loop
                    break
                try:
                    if isinstance(message, Command):
                        match message.ins:
                            case INS.SELECT:
                                await self.handle_select(message)
                            case INS.AUTH0:
                                await self.handle_auth0(message)
                            case INS.AUTH1:
                                await self.handle_auth1(message)
                            case INS.LOAD_CERT:
                                await self.handle_load_cert(message)
                            case INS.CONTROL_FLOW:
                                await self.handle_control_flow(message)
                                await self.transaction_termination()
                                break
                            case INS.EXCHANGE:
                                await self.handle_exchange(message)
                            case INS.ENVELOPE:
                                await self.handle_envelope(message)
                            case _:
                                raise NotImplementedError(
                                    "command: {} not implemented".format(message.ins)
                                )
                    else:
                        await self.handle_ble_messages(message)
                except AccessProtocolError as error:
                    Global.logger.error(
                        "restarting session because of error: {}".format(repr(error))
                    )
                    # main loop should continue even when commands are not valid
                    break
                except NoDeviceConnectedError:
                    # try to reconnect in outer loop
                    break

    async def ranging_loop(self) -> None:
        while True:
            try:
                Global.logger.info("Waiting for ranging session setup")
                payload, header, id = await self.transport_protocol.get_message()
                if header is not None and id is not None:
                    message = BleMessage(header, id, payload)
                else:
                    raise UnexpectedMessageTypeError
                if (header == ProtocolType.NOTIFICATION) and (
                    id == Notification_ID.EVENT) and (
                    payload is not None and payload[0] == Event_AttributeID.BUSY):
                    # Received busy event
                    if True == self.transport_protocol.was_timer_started():
                        continue
            except NoDeviceConnectedError:
                break
            except TimeoutError:
                await self.handle_timeout()
                raise TimeoutError
            # await self.transport_protocol.start_ranging()
            await self.handle_ble_messages(message)

    async def single_transaction(self, terminate_at_end: bool = True) -> None:
        """
        Handles a single transaction.
        Returns when completed or an error occurred.
        """
        await self.transaction_initiation()
        while True:
            try:
                if self.session is None:
                    raise SessionError("starting session failed")
                message = await self.wait_for_message()
                if isinstance(message, BleMessage) and (message.header == ProtocolType.NOTIFICATION) and (
                    message.id == Notification_ID.EVENT) and (
                    message.payload is not None and message.payload[0] == Event_AttributeID.BUSY):
                    # Received busy event
                    if True == self.transport_protocol.was_timer_started():
                        continue
            except(InvalidAIDError, InvalidINSError) as error:
                Global.logger.info(f"Caught exception: {error}")
                # retry wait for message
                continue
            except (InvalidCommandError, VerificationError):
                await self.failure_process(StatusBytes.COMMAND_NOT_COMPLIANT)
                return
            except NoDeviceConnectedError:
                return
            try:
                if isinstance(message, Command):
                    if (
                        self.mailbox_session.is_started()
                        and message.ins != INS.EXCHANGE
                    ):
                        await self.failure_process(StatusBytes.COMMAND_NOT_ALLOWED)
                        raise AccessProtocolError(
                            "received non-EXCHANGE command while an atomic session was "
                            "open"
                        )
                    match message.ins:
                        case INS.SELECT:
                            await self.handle_select(message)
                        case INS.AUTH0:
                            await self.handle_auth0(message)
                        case INS.AUTH1:
                            await self.handle_auth1(message)
                        case INS.LOAD_CERT:
                            await self.handle_load_cert(message)
                        case INS.CONTROL_FLOW:
                            await self.handle_control_flow(message)
                            if terminate_at_end:
                                await self.transaction_termination()
                            return
                        case INS.EXCHANGE:
                            await self.handle_exchange(message)
                        case INS.ENVELOPE:
                            await self.handle_envelope(message)
                        case _:
                            raise NotImplementedError(
                                "command: {} not implemented".format(message.ins)
                            )
                else:
                    completed = await self.handle_ble_messages(message)
                    if completed:
                        if terminate_at_end:
                            await self.transaction_termination()
                        return
            except AccessProtocolError as error:
                Global.logger.error(
                    "restarting session because of error: {}".format(repr(error))
                )
                await self.failure_process(StatusBytes.COMMAND_NOT_COMPLIANT)
                return
            except NoDeviceConnectedError:
                return

    async def handle_ble_messages(self, message: BleMessage) -> bool:
        """Handles ble messages

        Args:
            message (BleMessage): The message to handle

        Raises:
            UnexpectedBLEMessageError: raised when the messages is unknown

        Returns:
            bool: True when the access protocol is completed, else False
        """
        Global.logger.info("Handling (non command) ble message")
        if (
            message.header == ProtocolType.NOTIFICATION
            and message.id == Notification_ID.READER_STATUS_CHANGED
        ):
            self.handle_reader_status_changed_message(message)
            return True
        elif (message.header == ProtocolType.NOTIFICATION and message.id == Notification_ID.RANGING
        ):
            message.parse_payload(self.session.get_ble_encryption())
            match message.attribute.id:
                case RangingMessage_AttributeID.INITIATE_RANGING_SESSION_RESUME:
                    await self.send_ranging_session_resume_request()
                case RangingMessage_AttributeID.RANGING_SESSION_SUSPENDED:
                    await self.send_ranging_session_suspend_request()
                case RangingMessage_AttributeID.INITIATE_RANGING_SESSION_SETUP_LATER | RangingMessage_AttributeID.INITIATE_RANGING_SESSION_RESUME_LATER | RangingMessage_AttributeID.SECURE_RANGING_OVER_UWB_RADIO_FAILED:
                    raise NotImplementedError
            return True
        elif (
            message.header == ProtocolType.NOTIFICATION
            and message.id == Notification_ID.READER_STATUS_ACCESS_PROTOCOL_COMPLETED
        ):
            self.handle_reader_status_access_protocol_completed_message(message)
            return True
        elif (
            message.header == ProtocolType.NOTIFICATION
            and message.id == Notification_ID.EVENT
        ):
            self.handle_event_message(message)
        elif (
            message.header == ProtocolType.UWB_RANGING_SERVICE
            and message.id == UWB_RangingService_ID.RANGING_SESSION_SETUP_M1
        ):
            await self.handle_ranging_setup_m1(message)
        elif (
            message.header == ProtocolType.UWB_RANGING_SERVICE
            and message.id == UWB_RangingService_ID.RANGING_SESSION_SETUP_M3
        ):
            await self.handle_ranging_setup_m3(message)
            await self.transport_protocol.start_ranging()
        elif (
            message.header == ProtocolType.UWB_RANGING_SERVICE
            and message.id == UWB_RangingService_ID.RANGING_SESSION_SUSPEND_REQUEST
        ):
            await self.handle_ranging_session_suspend_request(message)
        elif (
            message.header == ProtocolType.UWB_RANGING_SERVICE
            and message.id == UWB_RangingService_ID.RANGING_SESSION_SUSPEND_RESPONSE
        ):
            await self.handle_ranging_session_suspend_response(message)
        elif (
            message.header == ProtocolType.UWB_RANGING_SERVICE
            and message.id == UWB_RangingService_ID.RANGING_SESSION_RESUME_REQUEST
        ):
            await self.handle_ranging_session_resume_request(message)
        elif (
            message.header == ProtocolType.UWB_RANGING_SERVICE
            and message.id == UWB_RangingService_ID.RANGING_SESSION_RESUME_RESPONSE
        ):
            await self.handle_ranging_session_resume_response(message)
        else:
            raise UnexpectedBLEMessageError(
                "Received unhandleable ble message",
                message.header,
                message.id,
            )
        return False

    def select_pulseshape_combo(
        self, pulseshape_received: bytes, pulseshape_capability: bytes
    ) -> int | None:
        # convert bytes to sets of unique bytes
        set1 = set(pulseshape_received)
        set2 = set(pulseshape_capability)

        # Find common intersection of two sets
        common_bytes = set1.intersection(set2)

        # Return the first common byte found in the order of pulseshape_received
        for byte in pulseshape_received:
            if (byte in common_bytes) and (byte in pulse_shape_combo):
                return byte

        return None

    def select_config_id(self, config_id: bytes, supported_config_id: bytes) -> int:
        # convert bytes to sets of unique bytes
        set1 = set(config_id)
        set2 = set(supported_config_id)

        # Find common intersection of two sets
        common_bytes = set1.intersection(set2)

        for byte in config_id:
            if byte in common_bytes:
                return byte

        return None

    async def handle_ranging_setup_m1(self, message: BleMessage) -> None:
        Global.logger.info("Handling ranging session setup message M1")
        try:
            message.parse_payload(self.session.get_ble_encryption())
        except (BLEMessageError, IndexError) as error:
            # Incorrect attributes passed
            await self.send_event(Event_AttributeID.GENERAL_ERROR, GeneralError_Values.WRONG_PARAMETERS)
            return

        # Configure selected configuration ID
        self.selected_config_id = self.select_config_id(
            message.uwb_configuration_id.value,
            self.transport_protocol.get_uwb_config_id_support().to_bytes(2, "big")
        )
        if self.selected_config_id is not None:
            await self.transport_protocol.set_uwb_config_id(self.selected_config_id)

        # Configure selected pulse shape combo for the user device
        self.selected_pulse_shape_combination = self.select_pulseshape_combo(
            message.pulse_shape_combo.value,
            self.transport_protocol.get_pulse_shape_combination_support().to_bytes(
                3, "big"
            ),
        )
        if self.selected_pulse_shape_combination is not None:
            await self.transport_protocol.set_pulse_shape_combination(
                self.selected_pulse_shape_combination
            )
        else:
            raise InvalidPulseShapeCombo

        await self.transport_protocol.set_channel_bitmask(
            int.from_bytes(message.channel_bitmask.value, "big")
        )
        received_session_id = int.from_bytes(message.uwb_session_id.value, "big")
        uwb_session_id = self.transport_protocol.get_uwb_session_id()
        if received_session_id != uwb_session_id:
            raise InvalidUWBSessionId

        await self.send_ranging_session_setup_m2()

    async def set_hopping_conf(self, common_hopping_conf: int) -> None:
        if common_hopping_conf & HoppingConfig.NO_HOPPING:
            await self.transport_protocol.set_hopping_mode(UCIHoppingConfig.NO_HOPPING)
        elif common_hopping_conf & HoppingConfig.CONTINUOUS_HOPPING_MODULO:
            await self.transport_protocol.set_hopping_mode(UCIHoppingConfig.CONTINUOUS_HOPPING_MODULO)
        elif common_hopping_conf & HoppingConfig.ADAPTIVE_HOPPING_MODULO:
            await self.transport_protocol.set_hopping_mode(UCIHoppingConfig.ADAPTIVE_HOPPING_MODULO)
        else:
            raise InvalidHoppingConfig

    async def handle_ranging_setup_m3(self, message: BleMessage) -> None:
        Global.logger.info("Handling ranging session setup message M3")
        try:
            message.parse_payload(self.session.get_ble_encryption())
        except (BLEMessageError, IndexError) as error:
            # Incorrect attributes passed
            await self.send_event(Event_AttributeID.GENERAL_ERROR, GeneralError_Values.WRONG_PARAMETERS)
            return

        await self.transport_protocol.set_ran_multiplier(
            int.from_bytes(message.ran_multiplier.value, "big")
        )
        slot_duration = (
            int.from_bytes(message.number_chaps_per_slot.value, "big") / 3 * 1200
        )
        await self.transport_protocol.set_slot_duration(int(slot_duration))
        await self.transport_protocol.set_number_responders(
            int.from_bytes(message.number_responder_nodes.value, "big")
        )
        await self.transport_protocol.set_slots_per_round(
            int.from_bytes(message.number_slots_per_round.value, "big")
        )

        sync_code_bitmask = int.from_bytes(message.sync_code_index_bitmask.value, "big")
        sync_codes = []
        for bit_index in range(32):
            if sync_code_bitmask & (1 << bit_index):
                sync_codes.append(bit_index + 1)

        # pick the first sync code in the list
        await self.transport_protocol.set_sync_code_index(sync_codes[0])

        await self.set_hopping_conf(
            int.from_bytes(message.hopping_configuration_bitmask.value, "big")
        )
        await self.transport_protocol.set_mac_mode(int.from_bytes(message.mac_mode.value, "big"))

        await self.send_ranging_session_setup_m4()

    async def handle_ranging_session_suspend_request(self, message: BleMessage) -> None:
        Global.logger.info("Handling ranging session suspend request")
        try:
            message.parse_payload(self.session.get_ble_encryption())
            await self.send_ranging_session_suspend_response()
        except IndexError:
            # Mismatch in parameters
            # Generic error NTF with Wrong parameters
            await self.send_event(Event_AttributeID.GENERAL_ERROR, GeneralError_Values.WRONG_PARAMETERS)

    async def handle_ranging_session_suspend_response(
        self, message: BleMessage
    ) -> None:
        Global.logger.info("Handling ranging session suspend response")
        try:
            message.parse_payload(self.session.get_ble_encryption())
            await self.transport_protocol.stop_ranging()
        except IndexError:
            # Mismatch in parameters
            # Generic error NTF with Wrong parameters
            await self.send_event(Event_AttributeID.GENERAL_ERROR, GeneralError_Values.WRONG_PARAMETERS)

    async def handle_ranging_session_resume_request(self, message: BleMessage) -> None:
        Global.logger.info("Handling ranging session resume request")
        try:
            message.parse_payload(self.session.get_ble_encryption())
        except IndexError:
            # Mismatch in parameters
            # Generic error NTF with Wrong parameters
            await self.send_event(Event_AttributeID.GENERAL_ERROR, GeneralError_Values.WRONG_PARAMETERS)
            return None

        if message.uwb_session_id.value != int.from_bytes(self.session.transaction_identifier[-4:], "big"):
            # Mismatch in session ID
            # Generic error NTF with URSK not available
            await self.send_event(Event_AttributeID.GENERAL_ERROR, GeneralError_Values.URSK_UNAVAILABLE)
        else:
            await self.send_ranging_session_resume_response()

    async def handle_ranging_session_resume_response(self, message: BleMessage) -> None:
        Global.logger.info("Handling ranging session resume response")
        try:
            message.parse_payload(self.session.get_ble_encryption())
            await self.transport_protocol.start_ranging()
        except IndexError:
            # Mismatch in parameters
            # Generic error NTF with Wrong parameters
            await self.send_event(Event_AttributeID.GENERAL_ERROR, GeneralError_Values.WRONG_PARAMETERS)

    def start_new_session(self) -> None:
        """
        Start a new user session. Must be done before using handle commands.
        This sessions stores all information received from commands.
        Start a new session to delete all received info and start over.
        """
        Global.logger.info("Starting new session")
        self.session = UserSession(self.supported_versions, self.vendor_extension)

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

    async def failure_process(self, error_code: int) -> None:
        """
        Should be called when a failure state has occurred.
        returns an error code.
        Destroys all session bound keys and data.
        """
        response = self.apdu.create_error_response(error_code)
        await self.transport_protocol.send_message(response)

        await self.transaction_termination()

    async def send_initiate_access_protocol_notification(self, rke: bool = False) -> None:
        """
        Used by BLE, after a connection is established.
        """
        proprietary = create_proprietary_information(
            CSA_APPLICATION_TYPE,
            self.supported_versions,
        )
        proprietary_list: list[tuple[int, bytes | list]] = [
            (Select.PROPRIETARY_TAG, proprietary.to_bytes())
        ]
        proprietary_tlv = TLV(proprietary_list)
        message = BleMessage.create_initiate_access_protocol(proprietary_tlv.to_bytes(), rke=rke)
        await self.transport_protocol.send_message(message, timeout=self.timeout)
        
    async def send_rke_request(self, action: int = 0) -> None:
        """
        Used by BLE, after a connection is established to request RKE action.
        """
        message = BleMessage.create_rke_request(
            action.to_bytes(1, "big"),
            self.session.get_ble_encryption()
        )
        await self.transport_protocol.send_message(message)

    async def send_timesync(self) -> None:
        """
        This message is used by device to provide Bluetooth LE Timesync payload which
        includes, the 13 DeviceEventCount, the UWB Device Time timestamp and the UWB
        Device Time uncertainty.
        """
        if not isinstance(self.transport_protocol, BLEUWB):
            raise InvalidProtocolTypeError

        Global.logger.info("Sending time sync ble message")

        # Some values have been set to a default value,
        # and will need further investigation
        data_event_count = 0xFFFFFFFFFFFFFFFF
        uwb_dev_time = await self.transport_protocol.get_uwb_time0()
        uwb_dev_time_uncertainty = 0
        uwb_clk_skew_measurement_available = 0
        dev_ppm = 0
        success = 0
        retry_delay = 500
        message = BleMessage.create_time_sync(
            data_event_count,
            uwb_dev_time,
            uwb_dev_time_uncertainty,
            uwb_clk_skew_measurement_available,
            dev_ppm,
            success,
            retry_delay,
            self.session.get_ble_encryption(),
        )
        await self.transport_protocol.send_message(message)

    async def send_initiate_ranging(self) -> None:
        """
        Used to trigger the Reader to initiate a new UWB ranging session
        """
        if not isinstance(self.transport_protocol, BLEUWB):
            raise InvalidProtocolTypeError

        if not self.session.ursk_available:
            Global.logger.info("Sending general error URSK unavailable")
            await self.send_event(Event_AttributeID.GENERAL_ERROR, GeneralError_Values.URSK_UNAVAILABLE)
        else:
            Global.logger.info("Sending initiate ranging ble message")

            message = BleMessage.create_initiate_ranging_session(
                self.session.get_ble_encryption()
            )
            await self.transport_protocol.send_message(message, timeout=self.timeout)

    async def send_ranging_message_suspended(self) -> None:
        """
        Used to trigger the Reader to initiate a new UWB ranging session
        """
        if not isinstance(self.transport_protocol, BLEUWB):
            raise InvalidProtocolTypeError

        Global.logger.info("Sending ranging suspended ble message")

        message = BleMessage.create_ranging_messsage_suspended(
            self.session.get_ble_encryption()
        )
        await self.transport_protocol.send_message(message)

    async def send_ranging_message_resume(self) -> None:
        """
        Used to trigger the Reader to initiate a new UWB ranging session
        """
        if not isinstance(self.transport_protocol, BLEUWB):
            raise InvalidProtocolTypeError

        Global.logger.info("Sending ranging resume ble message")

        message = BleMessage.create_ranging_message_resume(
            self.session.get_ble_encryption()
        )
        await self.transport_protocol.send_message(message)
        
    async def send_ranging_session_setup_m2(self) -> None:
        if not isinstance(self.transport_protocol, BLEUWB):
            raise InvalidProtocolTypeError

        Global.logger.info("Sending ranging session setup M2 ble message")

        uwb_configuration_id = await self.transport_protocol.get_uwb_config_id()
        Global.logger.info(f"uwb_config_id = {uwb_configuration_id}")
        channel_bitmask = Channel.CHANNEL_9
        sync_code_index_bitmask = self.transport_protocol.get_sync_code_bitmask()
        ran_multiplier = await self.transport_protocol.get_ran_multiplier()
        slot_bitmask = self.transport_protocol.get_slot_bitmask()
        hopping_conf_bitmask = self.transport_protocol.get_hopping_config_bitmask()
        vendor_specific = 0xFF

        message = BleMessage.create_ranging_session_setup_m2(
            uwb_configuration_id,
            self.selected_pulse_shape_combination,
            channel_bitmask,
            sync_code_index_bitmask,
            ran_multiplier,
            slot_bitmask,
            hopping_conf_bitmask,
            vendor_specific,
            self.session.get_ble_encryption(),
        )
        await self.transport_protocol.send_message(message, timeout=self.timeout)

    async def send_ranging_session_setup_m4(self) -> None:
        if not isinstance(self.transport_protocol, BLEUWB):
            raise InvalidProtocolTypeError

        Global.logger.info("Sending ranging session setup M4 ble message")
        sts_index0 = await self.transport_protocol.get_sts_index0()
        uwb_time0 = await self.transport_protocol.get_uwb_time0()
        hop_mode_key = await self.transport_protocol.get_hop_mode_key()
        sync_code_index = await self.transport_protocol.get_sync_code_index()

        message = BleMessage.create_ranging_session_setup_m4(
            sts_index0,
            uwb_time0,
            hop_mode_key,
            sync_code_index,
            self.session.get_ble_encryption(),
        )
        await self.transport_protocol.send_message(message, timeout=self.timeout)

    async def send_ranging_session_suspend_request(self) -> None:
        if not isinstance(self.transport_protocol, BLEUWB):
            raise InvalidProtocolTypeError

        Global.logger.info("Sending ranging session suspend request ble message")
        uwb_session_id = self.transport_protocol.get_uwb_session_id()

        message = BleMessage.create_ranging_session_suspend_request(
            uwb_session_id,
            self.session.get_ble_encryption(),
        )
        await self.transport_protocol.send_message(message, timeout=self.timeout)

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
        await self.transport_protocol.send_message(message, timeout=self.timeout)

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

    async def send_event(self, attribute: Event_AttributeID, errorcode: int | None) -> None:
        if not isinstance(self.transport_protocol, BLEUWB):
            raise InvalidProtocolTypeError

        if self.session is None:
            raise SessionError("No Session")

        Global.logger.info("Sending event")

        if Event_AttributeID.BUSY == attribute:
            message = BleMessage.create_busy_event_message(self.session.get_ble_encryption())
        elif Event_AttributeID.GENERAL_ERROR == attribute:
            message = BleMessage.create_error_event_message(errorcode, self.session.get_ble_encryption())

        await self.transport_protocol.send_message(message)

    async def handle_select(self, select_command: Command) -> bytes:
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

        Global.logger.info("Handling Select Command")
        if select_command.aid == EXPEDITED_PHASE_AID:
            Global.logger.info(
                "AID valid for expedited phase: {!r}".format(
                    hexlify(select_command.aid)
                )
            )
            self.session.update_state(UserSessionState.SELECT_DONE)
        elif select_command.aid == STEPUP_PHASE_AID:
            Global.logger.info(
                "AID valid for step-up phase: {!r}".format(hexlify(select_command.aid))
            )
            if not self.session.state_valid(
                [UserSessionState.AUTH1_DONE, UserSessionState.EXCHANGE_DONE]
            ):
                raise AccessProtocolError(
                    "Step up phase can only be requested after standard expedited phase"
                )
            self.session.update_state(UserSessionState.SELECT_STEP_UP_DONE)
        else:
            Global.logger.warning("Invalid AID")
            await self.failure_process(StatusBytes.FILE_OR_APP_NOT_FOUND)
            raise InvalidAIDError(select_command.to_bytes(), select_command.aid)

        await self.response_select(
            select_command.aid,
            CSA_APPLICATION_TYPE,
            self.supported_versions,
        )
        Global.logger.info("Handling SELECT command done")

        return select_command.aid

    async def handle_auth0(self, auth0_command: Command) -> None:
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
        if not self.session.state_valid(UserSessionState.SELECT_DONE) and (
            self.transport_protocol_type != TransportProtocol.BLE_UWB
            and self.transport_protocol_type != TransportProtocol.SOCKET_BLE
        ):
            state = self.session.state
            await self.failure_process(StatusBytes.INVALID_INSTRUCTION)
            raise SessionError("unexpected state for auth0 command: {}".format(state))

        Global.logger.info("Handling AUTH0 Command")
        if (
            auth0_command.expedited_phase_protocol_version
            not in self.supported_versions
        ):
            await self.failure_process(StatusBytes.CONDITIONS_OF_USE_NOT_SATISFIED)
            raise VersionError
        else:
            Global.logger.info(
                "Requested version 0x{:04x} is supported (supported versions: {})".format(
                    auth0_command.expedited_phase_protocol_version,
                    ", ".join(str(hex(x)) for x in self.supported_versions),
                )
            )

        Global.logger.info("Saving AUTH0 data")
        try:
            self.session.set_auth0_data(auth0_command)
        except InvalidKeyError:
            raise AccessProtocolError("Reader ephemeral key is invalid")
        Global.logger.info("Reader ephemeral key is a valid key")

        # Setup UWB session id
        if (
            self.transport_protocol_type == TransportProtocol.BLE_UWB
            or self.transport_protocol_type == TransportProtocol.SOCKET_BLE
        ):
            if self.enable_uwb:
                await self.transport_protocol.driver.session_init(
                    session_id=self.session.transaction_identifier[-4:]
                )

        Global.logger.info("Looking up access credential")
        for access_credential in self.access_credentials:
            if access_credential.has_identifier(self.session.reader_group_identifier):
                self.session.set_access_credential(access_credential)
                Global.logger.info("Access credential found")
                try:
                    key = access_credential.get_reader_public_key(
                        self.session.reader_group_identifier
                    ).as_bytes()
                    Global.logger.info(
                        "Reader public key in access credential: {!r}".format(
                            hexlify(key)
                        )
                    )
                except KeyLookupFailed:
                    pass

                break
        else:
            raise AccessProtocolError(
                "Could not find key for reader identifier in access credential: "
                "{!r}".format(hexlify(self.session.reader_group_identifier))
            )
            
        if hasattr(auth0_command, "tlv_check"):
            command_status = auth0_command.tlv_check
        else:
            command_status = True

        if self.session.get_transaction_type() == Transaction.STANDARD:
            Global.logger.info("Standard transaction requested")
            self.session.update_state(UserSessionState.AUTH0_STD_DONE)

            await self.response_auth0(
                self.session.get_credential_epubkey().as_bytes(),
                command_status=command_status
            )
        elif self.session.get_transaction_type() == Transaction.FAST:
            Global.logger.info("Fast transaction requested")
            Global.logger.info("Looking for Kpersistent in storage")
            kpersistent = self.storage.find_kpersistent(
                self.session.reader_group_sub_identifier
            )
            if self.fast_transaction_implemented and kpersistent is not None:
                Global.logger.info(
                    "Kpersistent found: {!r}".format(hexlify(kpersistent))
                )
                Global.logger.info("Creating Cryptogram")
                self.session.derive_key_volatile_fast(
                    self.transport_protocol_type, kpersistent
                )
                self.session.create_encryption_engine_expedited()
                if self.transport_protocol_type in [
                    TransportProtocol.BLE_UWB,
                    TransportProtocol.SOCKET_BLE,
                ]:
                    Global.logger.info("Setting up BLE encryption")
                    self.session.set_ble_encryption(self.transport_protocol)
                    Global.logger.info("Setting up UWB secure ranging")
                    await self.transport_protocol.set_session_key(self.session.UR_SK)

                doc_timestamp = None
                revoke_timestamp = None
                if self.access_document is not None:
                    doc_timestamp = AccessDocument(self.access_document).get_timestamp()
                if self.revocation_document is not None:
                    revoke_timestamp = RevocationDocument(self.revocation_document).get_timestamp()
                cryptogram = compute_cryptogram(
                    self.session.cryptogram_SK,
                    signaling_bitmap=self.get_signaling_bitmap(),
                    credential_signed_timestamp=doc_timestamp,
                    revocation_signed_timestamp=revoke_timestamp,
                )
            else:
                Global.logger.info("Kpersistent not found, assigning random cryptogram")
                cryptogram = urandom(Auth0.CRYPTOGRAM_LEN)

            self.session.update_state(UserSessionState.AUTH0_FAST_DONE)

            await self.response_auth0(
                credential_epubk=self.session.get_credential_epubkey().as_bytes(),
                cryptogram=cryptogram,
                command_status=command_status
            )

        Global.logger.info("Handling AUTH0 command done")

    async def handle_auth0_with_wrong_tag_value(self, auth0_command: Command) -> None:
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
        if not self.session.state_valid(UserSessionState.SELECT_DONE) and (
            self.transport_protocol_type != TransportProtocol.BLE_UWB
            and self.transport_protocol_type != TransportProtocol.SOCKET_BLE
        ):
            state = self.session.state
            await self.failure_process(StatusBytes.INVALID_INSTRUCTION)
            raise SessionError("unexpected state for auth0 command: {}".format(state))

        Global.logger.info("Handling AUTH0 Command")
        if (
            auth0_command.expedited_phase_protocol_version
            not in self.supported_versions
        ):
            await self.failure_process(StatusBytes.CONDITIONS_OF_USE_NOT_SATISFIED)
            raise VersionError
        else:
            Global.logger.info(
                "Requested version 0x{:04x} is supported (supported versions: {})".format(
                    auth0_command.expedited_phase_protocol_version,
                    ", ".join(str(hex(x)) for x in self.supported_versions),
                )
            )

        Global.logger.info("Saving AUTH0 data")
        try:
            self.session.set_auth0_data(auth0_command)
        except InvalidKeyError:
            raise AccessProtocolError("Reader ephemeral key is invalid")
        Global.logger.info("Reader ephemeral key is a valid key")

        # Setup UWB session id
        if (
            self.transport_protocol_type == TransportProtocol.BLE_UWB
            or self.transport_protocol_type == TransportProtocol.SOCKET_BLE
        ):
            if self.enable_uwb:
                await self.transport_protocol.driver.session_init(
                    session_id=self.session.transaction_identifier[-4:]
                )

        Global.logger.info("Looking up access credential")
        for access_credential in self.access_credentials:
            if access_credential.has_identifier(self.session.reader_group_identifier):
                self.session.set_access_credential(access_credential)
                Global.logger.info("Access credential found")
                try:
                    key = access_credential.get_reader_public_key(
                        self.session.reader_group_identifier
                    ).as_bytes()
                    Global.logger.info(
                        "Reader public key in access credential: {!r}".format(
                            hexlify(key)
                        )
                    )
                except KeyLookupFailed:
                    pass

                break
        else:
            raise AccessProtocolError(
                "Could not find key for reader identifier in access credential: "
                "{!r}".format(hexlify(self.session.reader_group_identifier))
            )
            
        if hasattr(auth0_command, "tlv_check"):
            command_status = auth0_command.tlv_check
        else:
            command_status = True

        if self.session.get_transaction_type() == Transaction.STANDARD:
            Global.logger.info("Standard transaction requested")
            self.session.update_state(UserSessionState.AUTH0_STD_DONE)

            await self.response_auth0_with_wrong_tag_value(
                self.session.get_credential_epubkey().as_bytes(),
                command_status=command_status
            )
        elif self.session.get_transaction_type() == Transaction.FAST:
            Global.logger.info("Fast transaction requested")
            Global.logger.info("Looking for Kpersistent in storage")
            kpersistent = self.storage.find_kpersistent(
                self.session.reader_group_sub_identifier
            )
            if self.fast_transaction_implemented and kpersistent is not None:
                Global.logger.info(
                    "Kpersistent found: {!r}".format(hexlify(kpersistent))
                )
                Global.logger.info("Creating Cryptogram")
                self.session.derive_key_volatile_fast(
                    self.transport_protocol_type, kpersistent
                )
                self.session.create_encryption_engine_expedited()
                if self.transport_protocol_type in [
                    TransportProtocol.BLE_UWB,
                    TransportProtocol.SOCKET_BLE,
                ]:
                    Global.logger.info("Setting up BLE encryption")
                    self.session.set_ble_encryption(self.transport_protocol)

                doc_timestamp = None
                revoke_timestamp = None
                if self.access_document is not None and isinstance(
                    self.access_document, AccessDocument
                ):
                    doc_timestamp = self.access_document.get_timestamp()
                if self.revocation_document is not None and isinstance(
                    self.revocation_document, RevocationDocument
                ):
                    revoke_timestamp = self.revocation_document.get_timestamp()
                cryptogram = compute_cryptogram(
                    self.session.cryptogram_SK,
                    signaling_bitmap=self.get_signaling_bitmap(),
                    credential_signed_timestamp=doc_timestamp,
                    revocation_signed_timestamp=revoke_timestamp,
                )
            else:
                Global.logger.info("Kpersistent not found, assigning random cryptogram")
                cryptogram = urandom(Auth0.CRYPTOGRAM_LEN)

            self.session.update_state(UserSessionState.AUTH0_FAST_DONE)

            await self.response_auth0_with_wrong_tag_value(
                credential_epubk=self.session.get_credential_epubkey().as_bytes(),
                cryptogram=cryptogram,
                command_status=command_status
            )

        Global.logger.info("Handling AUTH0 command done")

    async def handle_load_cert(self, load_cert_command: Command) -> None:
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
            state = self.session.state
            await self.failure_process(StatusBytes.INVALID_INSTRUCTION)
            raise SessionError(
                "unexpected state for load cert command: {}".format(state)
            )

        Global.logger.info("Handling LOAD CERT Command")
        Global.logger.info("Decompressing and verifying certificate")

        reader_issuer_public_key = self.session.get_reader_group_identifier_key()
        self.session.set_cert_and_verify(
            load_cert_command.reader_cert, reader_issuer_public_key
        )
        self.chaining_command = load_cert_command.chaining
        await self.response_load_cert()

        if self.mode == UserMode.TEST and not self.session.cert_decoded:
            raise AccessProtocolError("Certificate decoding failed")
        if self.mode == UserMode.TEST and not self.session.cert_verified:
            raise AccessProtocolError("Certificate verification failed")

        Global.logger.info("Handling LOAD CERT command done")

    async def handle_auth1(self, auth1_command: Command, extra_tlv: bytes | None = None,) -> None:
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
            state = self.session.state
            await self.failure_process(StatusBytes.INVALID_INSTRUCTION)
            raise SessionError("unexpected state for auth1 command: {}".format(state))

        Global.logger.info("Handling AUTH1 Command")
        if auth1_command.certificate_data is not None:
            Global.logger.info("AUTH1 Command contains certificate")

            reader_issuer_public_key = self.session.get_reader_group_identifier_key()
            self.session.set_cert_and_verify(
                auth1_command.certificate_data, reader_issuer_public_key
            )

        if hasattr(self.session, "cert_decoded") and not self.session.cert_decoded:
            Global.logger.error("Error decoding certificate")
            await self.failure_process(StatusBytes.GENERIC_ERROR)
            raise AccessProtocolError("Certificate decoding failed")
        if hasattr(self.session, "cert_verified") and not self.session.cert_verified:
            Global.logger.error("Error verifying certificate")
            await self.failure_process(StatusBytes.SECURITY_STATUS_NOT_SATISFIED)
            raise AccessProtocolError("Certificate verification failed")

        await self.check_reader_authentication_data(auth1_command.reader_signature)

        try:
            Global.logger.info("Creating shared keys")
            self.session.set_shared_key()
            self.session.derive_key_volatile(self.transport_protocol_type)
            if self.transport_protocol_type in [
                TransportProtocol.BLE_UWB,
                TransportProtocol.SOCKET_BLE,
            ]:
                Global.logger.info("Setting up BLE encryption")
                self.session.set_ble_encryption(self.transport_protocol)
                Global.logger.info("Setting up UWB secure ranging")
                await self.transport_protocol.set_session_key(self.session.UR_SK)

            Global.logger.info("Creating Kpersistent")
            self.storage.add_kpersistent(
                kpersistent=self.session.derive_key_persistent(
                    self.transport_protocol_type
                ),
                reader_group_sub_id=self.session.reader_group_sub_identifier,
            )
        except KeyLookupFailed as error:
            # could not find reader public key
            await self.failure_process(StatusBytes.GENERIC_ERROR)
            raise error

        Global.logger.info("Creating user device authentication")
        device_authentication = create_user_device_authentication(
            self.session.reader_identifier,
            self.session.get_credential_epubkey(),
            self.session.reader_epubk,
            self.session.transaction_identifier,
        )
        signature = self.session.access_credential.sign(
            device_authentication.to_bytes()
        )
        Global.logger.debug(
            "Created user device authentication_data signature: {!r}".format(
                hexlify(signature)
            )
        )

        if self.session.encryption_expedited is None:
            raise AccessProtocolError("no encryption engine found")

        self.session.update_state(UserSessionState.AUTH1_DONE)
        self.chaining_command = auth1_command.chaining

        doc_timestamp = None
        revoke_timestamp = None
        if self.access_document is not None:
            doc_timestamp = AccessDocument(self.access_document).get_timestamp()
        if self.revocation_document is not None:
            revoke_timestamp = RevocationDocument(self.revocation_document).get_timestamp()

        await self.response_auth1(
            self.session.access_credential.get_key_slot(),
            self.session.access_credential.get_access_credential_public_key().as_bytes(),
            auth1_command.expected_response,
            signature,
            self.session.encryption_expedited,
            StatusBytes.SUCCESS,
            signaling_bitmap=self.get_signaling_bitmap(),
            credential_signed_timestamp=doc_timestamp,
            revocation_signed_timestamp=revoke_timestamp,
            extra_tlv=extra_tlv,
        )

        Global.logger.info("Handling AUTH1 command done")

    async def check_reader_authentication_data(self, reader_signature: bytes) -> None:
        if self.session is None:
            raise SessionError("No Session")

        Global.logger.info("Checking reader authentication data")
        reader_authentication = create_reader_authentication(
            self.session.reader_identifier,
            self.session.get_credential_epubkey(),
            self.session.reader_epubk,
            self.session.transaction_identifier,
        )
        Global.logger.debug(
            "verifying with signature: {!r}".format(hexlify(reader_signature))
        )
        intermediate_public_key = self.session.get_reader_public_key()
        Global.logger.debug(
            "verifying with key: {!r}".format(
                hexlify(intermediate_public_key.as_bytes())
            )
        )
        verified = intermediate_public_key.verify(
            reader_authentication.to_bytes(), reader_signature
        )
        if not verified:
            await self.failure_process(StatusBytes.SECURITY_STATUS_NOT_SATISFIED)
            raise AccessProtocolError("reader authentication data verification failed")
        Global.logger.info("reader authentication data verified successfully")

    async def handle_exchange(self, exchange_command: Command) -> None:
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
        if not self.session.state_valid(
            [
                UserSessionState.AUTH0_FAST_DONE,
                UserSessionState.AUTH1_DONE,
                UserSessionState.EXCHANGE_DONE,
                UserSessionState.ENVELOPE_DONE,
                UserSessionState.STEPUP_EXCHANGE_DONE,
                UserSessionState.SELECT_STEP_UP_DONE,
            ]
        ):
            state = self.session.state
            await self.failure_process(StatusBytes.INVALID_INSTRUCTION)
            raise SessionError(
                "unexpected state for exchange command: {}".format(state)
            )

        Global.logger.info("Handling EXCHANGE Command")
        if self.session.state_valid(
            [
                UserSessionState.ENVELOPE_DONE,
                UserSessionState.STEPUP_EXCHANGE_DONE,
            ]
        ):
            encryption = self.session.encryption_stepup
        else:
            encryption = self.session.encryption_expedited
        if encryption is None:
            raise AccessProtocolError("no encryption engine found")

        if not encryption.check_counters_valid():
            # End current session
            await self.failure_process(StatusBytes.INVALID_INSTRUCTION)
            return

        if self.session.state_valid(
            [
                UserSessionState.ENVELOPE_DONE,
                UserSessionState.STEPUP_EXCHANGE_DONE,
            ]
        ):
            self.session.update_state(UserSessionState.STEPUP_EXCHANGE_DONE)
        else:
            self.session.update_state(UserSessionState.EXCHANGE_DONE)

        if (
            self.transport_protocol_type == TransportProtocol.BLE_UWB
            or self.transport_protocol_type == TransportProtocol.SOCKET_BLE
        ) and exchange_command.reader_status is not None:
            raise AccessProtocolError(
                "EXCHANGE command has reader status tag while using BLE"
            )
        elif exchange_command.reader_status is not None:
            Global.logger.info(
                "Received reader status: 0x{:04x}, transaction is completed".format(
                    exchange_command.reader_status.value
                )
            )
            self.session.update_state(UserSessionState.TRANSACTION_COMPLETE)

        if exchange_command.ursk is not None:
            self.session.set_ursk()

        if (
            len(exchange_command.read_requests)
            + len(exchange_command.write_requests)
            + len(exchange_command.set_requests)
            > 0
        ):
            if self.mailbox is None:
                await self.return_exchange_error_and_close_channel(encryption)
                raise AccessProtocolError(
                    "Read, write or set request received, but no mailbox is present"
                )

            if (
                self.session.state_valid(UserSessionState.ENVELOPE_DONE)
                and not self.mailbox.step_up_permission
            ):
                raise AccessProtocolError(
                    "Read, write or set request received, but mailbox does not give "
                    "read/write permission for step up phase"
                )

            if (
                len(exchange_command.read_requests) > 0
                and not self.mailbox.read_permission
            ):
                raise AccessProtocolError(
                    "Read request received, but mailbox does not give read permission"
                )

            if (
                len(exchange_command.write_requests)
                + len(exchange_command.set_requests)
                > 0
            ) and not self.mailbox.write_permission:
                raise AccessProtocolError(
                    "Write and/or set request received, but mailbox does not give "
                    "write permission"
                )

            Global.logger.info("Checking boundaries of read, write and set commands")
            for read in exchange_command.read_requests:
                if read is None:
                    raise AccessProtocolError
                if not self.mailbox.check_boundaries(
                    int.from_bytes(read[0:2], "big"), int.from_bytes(read[2:4], "big")
                ):
                    await self.return_exchange_error_and_close_channel(encryption)
                    raise AccessProtocolError("Read request out of mailbox boundaries")

            for write in exchange_command.write_requests:
                if write is None:
                    raise AccessProtocolError
                if not self.mailbox.check_boundaries(
                    int.from_bytes(write[0:2], "big"), len(write) - 2
                ):
                    await self.return_exchange_error_and_close_channel(encryption)
                    raise AccessProtocolError("Write request out of mailbox boundaries")

            for set in exchange_command.set_requests:
                if set is None:
                    raise AccessProtocolError
                if not self.mailbox.check_boundaries(
                    int.from_bytes(set[0:2], "big"), int.from_bytes(set[2:4], "big")
                ):
                    await self.return_exchange_error_and_close_channel(encryption)
                    raise AccessProtocolError("Set request out of mailbox boundaries")

        Global.logger.info("Handling notifications")
        if exchange_command.notify is not None:
            tlvList = TLV.to_tlv_list(TLV.from_bytes(exchange_command.notify).to_data())
            if len(tlvList) > 1:
                Global.logger.info("Too much sub-TLVs for EXCHANGE[Notify], found {}.".format(len(tlvList)))
                raise AccessProtocolError
            else:
                # Get the (only) tag
                tlv = TLV.from_bytes(exchange_command.notify)
                tag = tlv.to_tag()

            Global.logger.info("Sub TLV tag detected: " + str(hex(tag)))
            if tag == 0xC1:
                errors = []
                errors = tlv.get_all_bytes_of_tag(0xC1)
                for error in errors:
                    if error is None:
                        raise AccessProtocolError
                    Global.logger.info("received error notification: {!r}".format(hexlify(error)))
            else:
                if tag == 0xC2:
                    descriptor = []
                    descriptor = tlv.get_all_bytes_of_tag(0xC2)
                    Global.logger.info("received Reader descriptor: ", hexlify(b''.join(descriptor)).decode())
                else:
                    if tag & 0x9F00 != 0x9F00:
                        Global.logger.info("tag does not match with 0xC1 or 0x9Fxx")
                        raise AccessProtocolError
                    else:
                        Global.logger.info("Notify Credential Issuer backend or application")
                        if tag & 0x9FC0 == 0x9F00:
                            Global.logger.info("Request to send data to a bound application on User Device")
                        else:
                            if tag & 0x9FC0 == 0x9F40:
                                Global.logger.info("Request to send data to the Credential Issuer backend")
                                if tag & 0x9F10 == 0x9F10:
                                    Global.logger.info("Request is time sensitive")
                                else:
                                    Global.logger.info("Request is not time sensitive")
                                importanceLevel = tag & 0x0007
                                if 0 <= importanceLevel < 5:
                                    Global.logger.info("Importance level: {}".format(importanceLevel))
                                else:
                                    Global.logger.info("Invalid importance level {}".format(importanceLevel))
                                    raise AccessProtocolError
                            else:
                                Global.logger.info("Invalid tag")
                                raise AccessProtocolError

        Global.logger.info("Handling read requests")
        read_data: list[tuple[int, bytes]] = []
        if self.mailbox is not None:
            for read in exchange_command.read_requests:
                mailbox_read = self.mailbox.read(
                    int.from_bytes(read[:2], "big"),
                    int.from_bytes(read[2:4], "big"),
                )
                read_data.append((len(mailbox_read), mailbox_read))

        Global.logger.info("Handling write and set requests")
        if self.mailbox is not None and exchange_command.atomic_session is not None:
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

        Global.logger.info("Generating response payload")
        exchange_payload = bytearray()
        for read_command in read_data:
            exchange_payload.extend(read_command[0].to_bytes(2, "big"))
            exchange_payload.extend(read_command[1])
        exchange_payload.extend(bytes([0x00, 0x02, 0x00, 0x00]))

        await self.response_exchange(exchange_payload, encryption)

        Global.logger.info("Handling EXCHANGE command done")

    async def return_exchange_error_and_close_channel(
        self, encryption: EncryptionEngine
    ) -> None:
        """
        Return an exchange error and close the channel.
        Used when an exchange fails.

        Raises:
            SessionError: Raised if no session is found.
            AccessProtocolError: Raised if no encryption engine is found.
        """
        if self.session is None:
            raise SessionError("No Session")

        Global.logger.info("Generating response payload with error")
        exchange_payload = bytes.fromhex("0002FFFF")
        await self.response_exchange(exchange_payload, encryption)

    async def handle_control_flow(self, control_flow_command: Command) -> None:
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

        Global.logger.info("Handling CONTROL FLOW Command")
        if control_flow_command.s1 == 0x00:
            Global.logger.info("transaction finished with failure")
        elif control_flow_command.s2 == 0x02:
            Global.logger.info("transaction finished with success")

        self.session.update_state(UserSessionState.SELECT_DONE)

        await self.response_control_flow()

        Global.logger.info("Handling CONTROL FLOW command done")

    def handle_reader_status_changed_message(self, message: BleMessage) -> None:
        Global.logger.info("Handling Reader Status Changed message")
        message.check_header_and_id(
            ProtocolType.NOTIFICATION,
            Notification_ID.READER_STATUS_CHANGED,
        )
        message.parse_payload(self.session.get_ble_encryption())

    async def handle_envelope(self, envelope_command: Command) -> bytes:
        """
        Parse an envelope command and send the appropriate response.

        Args:
            envelope_command (Command): The command to respond to.

        Raises:
            SessionError: Raised when the session is missing or in an invalid state.
        """
        if envelope_command.ins != INS.ENVELOPE:
            raise AccessProtocolError(
                "Tried to handle envelope command, "
                "but received command is not a envelope command"
            )

        if self.session is None:
            raise SessionError("No Session")
        if not self.session.state_valid(
            [
                UserSessionState.AUTH1_DONE,
                UserSessionState.EXCHANGE_DONE,
                UserSessionState.ENVELOPE_DONE,
                UserSessionState.SELECT_STEP_UP_DONE,
            ]
        ):
            state = self.session.state
            await self.failure_process(StatusBytes.INVALID_INSTRUCTION)
            raise SessionError(
                "unexpected state for envelope command: {}".format(state)
            )

        Global.logger.info("Handling ENVELOPE Command")

        if self.session.encryption_stepup is None:
            raise AccessProtocolError("no encryption engine (step up) found")

        if self.access_document is None and self.revocation_document is None:
            # If both are empty, we still send a DeviceResponse
            Global.logger.warning("no access or revocation documents found")

        device_response = {
            "1": "1.0",
            "2": [],
            "3": 0,
        }

        if self.access_document is not None:
            device_response["2"].append(cbor2.loads(self.access_document))
        if self.revocation_document is not None:
            device_response["2"].append(cbor2.loads(self.revocation_document))

        device_response_cbor = cbor2.dumps(device_response)
        Global.logger.info(f"DeviceResponse: {device_response_cbor.hex()}")
        await self.response_envelope(
            device_response_cbor, self.session.encryption_stepup
        )

        self.session.update_state(UserSessionState.ENVELOPE_DONE)

        Global.logger.info("Handling ENVELOPE command done")
        return envelope_command.decrypted_payload

    def handle_reader_status_access_protocol_completed_message(
        self, message: BleMessage
    ) -> None:
        Global.logger.info("Handling Reader Status Access Protocol Completed message")
        message.check_header_and_id(
            ProtocolType.NOTIFICATION,
            Notification_ID.READER_STATUS_ACCESS_PROTOCOL_COMPLETED,
        )
        message.parse_payload(self.session.get_ble_encryption())

    def handle_event_message(self, message: BleMessage) -> None:
        Global.logger.info("Handling Event message")
        message.check_header_and_id(ProtocolType.NOTIFICATION, Notification_ID.EVENT)
        message.parse_payload(self.session.get_ble_encryption())
        if message.attribute.id == Event_AttributeID.GENERAL_ERROR:
            Global.logger.warning(
                "Received General Error, with reason: {}".format(
                    message.reason_code.name
                )
            )
            if hasattr(message, "reader_descriptor"):
                Global.logger.warning(
                    "Received Reader descriptor: {}".format(
                        message.reader_descriptor
                    )
                )
        else:
            raise NotImplementedError

    async def wait_for_ble_message(
        self,
        expected_command: INS | list[INS] | None = None,
    ) -> BleMessage:
        """
        Waits until a ble message is received.

        Args:
            expected_command (INS | list[INS] | None, optional): INS or list of INS with
            expected commands. raises UnexpectedCommandError if another command is
            received. Defaults to None.
            encryption (EncryptionEngine | None, optional): Used for decrypting
            messages.
            Not required for every command. Defaults to None.

        Raises:
            InvalidCLAError: Raised when the received command has an invalid CLA.
            InvalidParameterError: Raised when the received command has an invalid
            Parameter (P1 or P2).
            InvalidCommandError: Raised when the received command is invalid.
            VerificationError: Raised when the verification of an AES decryption fails.
            UnexpectedCommandError: when the command is not in expected_command.

        Returns:
            BleMessage: the received ble message.
        """
        message = await self.wait_for_message(expected_command)
        if not isinstance(message, BleMessage):
            raise AccessProtocolError(
                "Received unexpected command while waiting for BLE message : "
                "{!r}".format(hexlify(message.to_bytes()))
            )
        return message

    async def wait_for_command(
        self,
        expected_command: INS | list[INS] | None = None,
    ) -> Command:
        """
        Waits until a command is received, and parses the command.

        Args:
            expected_command (INS | list[INS] | None, optional): INS or list of INS with
            expected commands. raises UnexpectedCommandError if another command is
            received. Defaults to None.
            encryption (EncryptionEngine | None, optional): Used for decrypting
            messages.
            Not required for every command. Defaults to None.

        Raises:
            InvalidCLAError: Raised when the received command has an invalid CLA.
            InvalidParameterError: Raised when the received command has an invalid
            Parameter (P1 or P2).
            InvalidCommandError: Raised when the received command is invalid.
            VerificationError: Raised when the verification of an AES decryption fails.
            UnexpectedCommandError: when the command is not in expected_command.

        Returns:
            Command: the received command.
        """
        while True:
            try:
                message = await self.wait_for_message(expected_command)
                break
            except (InvalidAIDError, InvalidINSError) as error:
                Global.logger.info(f"Caught exception: {error}")
                # retry wait for message
        if not isinstance(message, APDUMessage):
            raise UnexpectedBLEMessageError(
                "Received unexpected ble message while waiting for "
                "AP request message",
                message.header,
                message.id,
            )
        return message

    async def wait_for_message(
        self,
        expected_command: INS | list[INS] | None = None,
    ) -> Command | BleMessage:
        """
        Waits until a message is received, and parses it if it is a command.

        Args:
            expected_command (INS | list[INS] | None, optional): INS or list of INS with
            expected commands. raises UnexpectedCommandError if another command is
            received. Defaults to None.

        Raises:
            InvalidCLAError: Raised when the received command has an invalid CLA.
            InvalidParameterError: Raised when the received command has an invalid
            Parameter (P1 or P2).
            InvalidCommandError: Raised when the received command is invalid.
            VerificationError: Raised when the verification of an AES decryption fails.
            UnexpectedCommandError: when the command is not in expected_command.

        Returns:
            Command: the received command.
        """
        if self.session is None:
            raise SessionError("No Session")

        if isinstance(expected_command, INS):
            expected_command = [expected_command]

        Global.logger.info("Waiting for command")
        try:
            command_str, header, id = await self.transport_protocol.get_message()
        except TimeoutError:
            await self.handle_timeout()
            raise TimeoutError

        if (header is None and id is None) or (
            header == ProtocolType.AP and id == AP_ID.AP_RQ
        ):
            Global.logger.info("Received command")
        elif header is not None and id is not None:
            Global.logger.info(
                "Received BLE message with header: 0x{:02x} and id: 0x{:02x}".format(
                    header, id
                )
            )
            return BleMessage(header, id, command_str)
        else:
            raise AccessProtocolError("Message invalid (missing header or id)")

        try:
            command = await self.apdu.handle_chaining_receive_command(
                command_str, self.transport_protocol, timeout=self.timeout
            )
        except TimeoutError:
            await self.handle_timeout()
            raise TimeoutError

        if (
            command.ins == INS.GET_DATA
            and (command.p1, command.p2) == (0x7F, 0x68)
        ):
            Global.logger.info("Received unexpected GET DATA command")
            response = self.apdu.create_error_response(StatusBytes.REFERENCED_DATA_NOT_FOUND)
            await self.transport_protocol.send_message(response)
            raise InvalidINSError(command.to_bytes())

        if (
            command.ins == INS.SELECT
            and command.p1 != 0x04
            and command.p2 != 0x00
        ):
            response = self.apdu.create_error_response(StatusBytes.INCORRECT_P1_P2)
            await self.transport_protocol.send_message(response)
            raise InvalidAIDError(command.to_bytes(), command.data)

        if (
            command.ins == INS.SELECT
            and command.data != EXPEDITED_PHASE_AID
            and command.data != STEPUP_PHASE_AID
        ):
            response = self.apdu.create_error_response(StatusBytes.FILE_OR_APP_NOT_FOUND)
            await self.transport_protocol.send_message(response)
            raise InvalidAIDError(command.to_bytes(), command.data)

        if self.session.state_valid(
            [
                UserSessionState.AUTH0_STD_DONE,
                UserSessionState.AUTH0_FAST_DONE,
            ]
        ):
            encryption = self.session.encryption_expedited
        elif (
            self.session.state_valid(
                [UserSessionState.EXCHANGE_DONE, UserSessionState.AUTH1_DONE]
            )
            and command.ins == INS.EXCHANGE
        ):
            encryption = self.session.encryption_expedited
        elif self.session.state_valid(
            [
                UserSessionState.AUTH1_DONE,
                UserSessionState.EXCHANGE_DONE,
                UserSessionState.SELECT_STEP_UP_DONE,
                UserSessionState.ENVELOPE_DONE,
                UserSessionState.STEPUP_EXCHANGE_DONE,
            ]
        ):
            encryption = self.session.encryption_stepup
        else:
            encryption = None

        try:
            command = self.apdu.parse_command(command, encryption)
        except InvalidCLAError as error:
            await self.failure_process(StatusBytes.FUNCTIONS_IN_CLA_NOT_SUPPORTED)
            raise error
        except InvalidParameterError as error:
            await self.failure_process(StatusBytes.INCORRECT_P1_P2)
            raise error
        except InvalidCommandError as error:
            await self.failure_process(StatusBytes.COMMAND_NOT_COMPLIANT)
            raise error
        except VerificationError as error:
            await self.failure_process(StatusBytes.SECURITY_STATUS_NOT_SATISFIED)
            raise error

        if expected_command is not None and command.ins not in expected_command:
            raise UnexpectedCommandError
        return command

    async def response_auth0(
        self,
        credential_epubk: bytes,
        cryptogram: bytes | None = None,
        command_status: bool = True,
    ) -> None:
        """
        Create and send an auth0 response.

        Args:
            credential_epubk (bytes): Access credential ephemeral public key.
            cryptogram (bytes | None, optional): authentication cryptogram.
            Defaults to None.
        """
        if command_status:
            status = StatusBytes.SUCCESS
        else:
            status = StatusBytes.COMMAND_NOT_COMPLIANT
            
        auth0_response = self.apdu.create_auth0_response(
            credential_epubk, status, cryptogram
        )
        Global.logger.info("Sending AUTH0 response")
        try:
            await self.apdu.handle_chaining_send_response(
                auth0_response, self.transport_protocol, timeout=self.timeout
            )
        except TimeoutError:
            await self.handle_timeout()
            raise TimeoutError


    async def response_auth0_with_wrong_tag_value(
        self,
        credential_epubk: bytes,
        cryptogram: bytes | None = None,
        command_status: bool = True,
    ) -> None:
        """
        Create and send an auth0 response.

        Args:
            credential_epubk (bytes): Access credential ephemeral public key.
            cryptogram (bytes | None, optional): authentication cryptogram.
            Defaults to None.
        """
        auth0_response = self.apdu.create_auth0_response_with_wrong_tag_value(
            credential_epubk, StatusBytes.SUCCESS, cryptogram
        )
        Global.logger.info("Sending AUTH0 response")
        await self.apdu.handle_chaining_send_response(
            auth0_response, self.transport_protocol
        )

    async def response_auth1(
        self,
        key_slot: bytes | None,
        credential_public_key: bytes | None,
        expected_response: Auth1Response,
        signature: bytes,
        encryption: EncryptionEngine,
        status: int = StatusBytes.SUCCESS,
        private_mailbox_data: bytes | None = None,
        signaling_bitmap: bytes | None = None,
        credential_signed_timestamp: bytes | None = None,
        revocation_signed_timestamp: bytes | None = None,
        check_validity: bool = True,
        extra_tlv: bytes | None = None,
    ) -> None:
        """
        Create and send an auth1 response.

        Args:
            key_slot (bytes | None): First 8 byes of the keyIdentifier.
            credential_public_key (bytes | None): Credential long term public key.
            expected_response (Auth1Response): expected response (keyslot or
            credential public key)
            signature (bytes): User device authentication signature.
            encryption (EncryptionEngine): Encryption engine to encrypt the response.
            status (int, optional): response status. Defaults to StatusBytes.SUCCESS.
            private_mailbox_data (bytes | None, optional): Defaults to None.
            signaling_bitmap (bytes | None, optional): Defaults to None.
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
            signaling_bitmap,
            credential_signed_timestamp,
            revocation_signed_timestamp,
            check_validity,
            extra_tlv,
        )
        Global.logger.info("Sending AUTH1 response")
        try:
            await self.apdu.handle_chaining_send_response(
                auth1_response, self.transport_protocol, timeout=self.timeout
            )
        except TimeoutError:
            await self.handle_timeout()
            raise TimeoutError

    async def response_select(
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
        Global.logger.info("Sending SELECT response")
        await self.apdu.handle_chaining_send_response(
            select_response, self.transport_protocol
        )

    async def response_envelope(
        self,
        document: bytes,
        encryption: EncryptionEngine,
    ) -> None:
        """
        Create and send a envelope response.
        """
        envelope_response = self.apdu.create_envelope_response(document, encryption)
        Global.logger.info("Sending ENVELOPE response")
        try:
            await self.apdu.handle_chaining_send_response(
                envelope_response, self.transport_protocol, timeout=self.timeout
            )
        except TimeoutError:
            await self.handle_timeout()
            raise TimeoutError

    async def response_load_cert(self) -> None:
        """
        Create and send a load cert response.
        """
        load_cert_response = self.apdu.create_load_cert_response(StatusBytes.SUCCESS)
        Global.logger.info("Sending LOAD CERT response")
        try:
            await self.apdu.handle_chaining_send_response(
                load_cert_response, self.transport_protocol, timeout=self.timeout
            )
        except TimeoutError:
            await self.handle_timeout()
            raise TimeoutError

    async def response_exchange(
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
        Global.logger.info("Sending EXCHANGE response")
        try:
            await self.apdu.handle_chaining_send_response(
                exchange_response, self.transport_protocol, timeout=self.timeout
            )
        except TimeoutError:
            await self.handle_timeout()
            raise TimeoutError

    async def response_control_flow(self) -> None:
        """
        Create and send a control flow response.
        """
        control_flow_response = self.apdu.create_control_flow_response(
            StatusBytes.SUCCESS
        )
        Global.logger.info("Sending CONTROL FLOW response")
        await self.apdu.handle_chaining_send_response(
            control_flow_response, self.transport_protocol
        )


class UserSessionState(Enum):
    SESSION_START = 1
    SELECT_DONE = 2
    AUTH0_STD_DONE = 3
    AUTH0_FAST_DONE = 4
    AUTH1_DONE = 5
    EXCHANGE_DONE = 6
    SELECT_STEP_UP_DONE = 7
    ENVELOPE_DONE = 8
    STEPUP_EXCHANGE_DONE = 9
    TRANSACTION_COMPLETE = 10


class UserSession:
    """
    Contains info from a single session (with one Reader Device)
    """

    def __init__(
        self,
        supported_version: list[int],
        vendor_extension: bytes | None = None,
    ) -> None:
        self.state = UserSessionState.SESSION_START
        self.supported_versions = supported_version
        self.encryption_expedited: EncryptionEngine | None = None
        self.encryption_stepup: EncryptionEngine | None = None
        self.command_vendor_extension: bytes | None = None
        self.response_vendor_extension = vendor_extension
        self.ursk_available: bool = False
        self.ble_encryption_engine: EncryptionEngine | None = None

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
        self.authentication_policy = auth0_command.authentication_policy
        self.expedited_phase_protocol_version = (
            auth0_command.expedited_phase_protocol_version
        )
        self.reader_epubk = PublicKey(auth0_command.reader_epubk)
        self.transaction_identifier = auth0_command.transaction_identifier
        self.reader_identifier = auth0_command.reader_identifier
        self.command_vendor_extension = auth0_command.vendor_specific_extension

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
        Global.logger.debug("Deriving key (volatile)")

        info = bytearray(
            self.credential_ephemeral.get_public_key().get_x().to_bytes(32, "big")
        )
        if self.command_vendor_extension is not None:
            info.append(Auth0.VENDOR_SPECIFIC_TAG)
            info.append(len(self.command_vendor_extension))
            info.extend(self.command_vendor_extension)
        if self.response_vendor_extension is not None:
            info.append(Auth0.RE_VENDOR_SPECIFIC_TAG)
            info.append(len(self.response_vendor_extension))
            info.extend(self.response_vendor_extension)

        proprietary_information = create_proprietary_information(
            CSA_APPLICATION_TYPE,
            self.supported_versions,
        ).to_bytes()
        salt = create_salt(
            transport_protocol=transport_protocol,
            word=b"Volatile****",
            reader_public_key=self.get_reader_group_identifier_key(),
            reader_ephemeral_public_key=self.reader_epubk,
            reader_identifier=self.reader_identifier,
            protocol_version=self.expedited_phase_protocol_version.to_bytes(2, "big"),
            transaction_identifier=self.transaction_identifier,
            flag=bytes([self.command_parameters, self.authentication_policy]),
            proprietary_information=proprietary_information,
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
        self, transport_protocol: TransportProtocol, k_persistent: bytes
    ) -> None:
        Global.logger.debug("Deriving key (volatile fast)")

        info = bytearray(
            self.credential_ephemeral.get_public_key().get_x().to_bytes(32, "big")
        )
        if self.command_vendor_extension is not None:
            info.append(Auth0.VENDOR_SPECIFIC_TAG)
            info.append(len(self.command_vendor_extension))
            info.extend(self.command_vendor_extension)
        if self.response_vendor_extension is not None:
            info.append(Auth0.RE_VENDOR_SPECIFIC_TAG)
            info.append(len(self.response_vendor_extension))
            info.extend(self.response_vendor_extension)

        proprietary_information = create_proprietary_information(
            CSA_APPLICATION_TYPE,
            self.supported_versions,
        ).to_bytes()
        salt = create_salt(
            transport_protocol=transport_protocol,
            word=b"VolatileFast",
            reader_public_key=self.get_reader_group_identifier_key(),
            reader_ephemeral_public_key=self.reader_epubk,
            reader_identifier=self.reader_identifier,
            protocol_version=self.expedited_phase_protocol_version.to_bytes(2, "big"),
            transaction_identifier=self.transaction_identifier,
            flag=bytes([self.command_parameters, self.authentication_policy]),
            proprietary_information=proprietary_information,
            credential_public_key=self.access_credential.get_access_credential_public_key(),
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

    def derive_key_persistent(self, transport_protocol: TransportProtocol) -> bytes:
        Global.logger.debug("Deriving key (persistent)")

        info = bytearray(
            self.credential_ephemeral.get_public_key().get_x().to_bytes(32, "big")
        )
        if self.command_vendor_extension is not None:
            info.append(Auth0.VENDOR_SPECIFIC_TAG)
            info.append(len(self.command_vendor_extension))
            info.extend(self.command_vendor_extension)
        if self.response_vendor_extension is not None:
            info.append(Auth0.RE_VENDOR_SPECIFIC_TAG)
            info.append(len(self.response_vendor_extension))
            info.extend(self.response_vendor_extension)

        proprietary_information = create_proprietary_information(
            CSA_APPLICATION_TYPE,
            self.supported_versions,
        ).to_bytes()
        salt = create_salt(
            transport_protocol=transport_protocol,
            word=b"Persistent**",
            reader_public_key=self.get_reader_group_identifier_key(),
            reader_ephemeral_public_key=self.reader_epubk,
            reader_identifier=self.reader_identifier,
            protocol_version=self.expedited_phase_protocol_version.to_bytes(2, "big"),
            transaction_identifier=self.transaction_identifier,
            flag=bytes([self.command_parameters, self.authentication_policy]),
            proprietary_information=proprietary_information,
            credential_public_key=self.access_credential.get_access_credential_public_key(),
        )
        derived_key = derive_key(self.shared_key, bytes(info), 32, salt)
        return derived_key[0:32]

    def create_encryption_engine_expedited(self) -> None:
        Global.logger.debug("Creating encryption engine for expedited phase")
        self.encryption_expedited = EncryptionEngine(
            DeviceType.USER, self.expedited_SK_reader, self.expedited_SK_device
        )

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
            DeviceType.USER, stepup_SK_reader, stepup_SK_device
        )

    def set_ble_encryption(self, transport_protocol: TransportProtocolBase) -> None:
        if not isinstance(transport_protocol, BLEUWB):
            raise AccessProtocolError("Trying to set BLE encryption while using NFC")

        selected_version, available_versions = transport_protocol.get_ble_versions()
        self.ble_encryption_engine = get_ble_encryption(
            DeviceType.USER, self.ble_SK, selected_version, available_versions
        )

    def get_ble_encryption(self) -> EncryptionEngine | None:
        return self.ble_encryption_engine

    def set_cert_and_verify(
        self, compressed_cert: bytes, public_key: PublicKey
    ) -> None:
        Global.logger.debug(
            "decompressing compressed certificate: {!r}".format(
                hexlify(compressed_cert)
            )
        )
        try:
            cert = Certificate.decode_compressed(compressed_cert)
        except CertificateDecodingError:
            self.cert_decoded = False
            return
        self.cert_decoded = True
        verified = cert.verify(public_key)
        if verified:
            Global.logger.info("Verification successfull")
            self.cert = cert
            self.cert_verified = True
        else:
            Global.logger.warning("Verification unsuccessfull")
            self.cert_verified = False

    def get_reader_public_key(self) -> PublicKey:
        Global.logger.debug("Looking for reader public key")

        if hasattr(self, "cert_decoded") and not self.cert_decoded:
            raise KeyLookupFailed("Cert received but decoding failed")

        if hasattr(self, "cert_verified") and not self.cert_verified:
            raise KeyLookupFailed("Cert received but verification failed")

        if hasattr(self, "cert"):
            Global.logger.info("Checking certificate")
            reader_public_key = self.cert.get_public_key()
            Global.logger.info(
                "get reader public key from certificate: {!r}".format(
                    hexlify(reader_public_key.as_bytes())
                )
            )
            return reader_public_key

        if hasattr(self, "access_credential"):
            Global.logger.info("Checking Access Credential")
            if self.access_credential.has_identifier(self.reader_group_identifier):
                reader_public_key = self.access_credential.get_reader_public_key(
                    self.reader_group_identifier
                )
                Global.logger.debug(
                    "Got reader public key from access_credentials: {!r}".format(
                        hexlify(reader_public_key.as_bytes())
                    )
                )
                return reader_public_key
        else:
            Global.logger.warning("No access credential set")
        raise KeyLookupFailed(
            "Could not find key for reader identifier: {!r}".format(
                hexlify(self.reader_group_identifier)
            )
        )

    def get_reader_group_identifier_key(self) -> PublicKey:
        Global.logger.debug("Looking for reader group identifier key")

        if hasattr(self, "access_credential"):
            Global.logger.info("Checking Access Credential")
            if self.access_credential.has_identifier(self.reader_group_identifier):
                try:
                    reader_public_key = self.access_credential.get_reader_public_key(
                        self.reader_group_identifier
                    )
                    Global.logger.debug(
                        "reader_group_identifier_key set to "
                        "reader public key: {!r}".format(
                            hexlify(reader_public_key.as_bytes())
                        )
                    )
                    return reader_public_key
                except KeyLookupFailed:
                    pass

            raise KeyLookupFailed(
                "reader group identifier not found in access credential"
            )
        raise KeyLookupFailed("No access credential set")

    def set_ursk(self) -> None:
        if self.ursk_available:
            raise AccessProtocolError("Making the URSK available can only be done once")
        else:
            self.ursk_available = True


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
