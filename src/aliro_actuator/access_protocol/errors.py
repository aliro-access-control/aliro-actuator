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

from aliro_actuator.access_protocol.defines import EXPEDITED_PHASE_AID, STEPUP_PHASE_AID


class AccessProtocolError(Exception):
    """
    Parent class of all errors related to the access protocol.
    """

    pass


class CryptogramNotFound(AccessProtocolError):
    pass


class SessionError(AccessProtocolError):
    pass


class UnexpectedNotificationDataError(AccessProtocolError):
    def __init__(self, response: bytes, other_info: str = ""):
        if other_info != "":
            message = "{}, Data: {!r}".format(other_info, hexlify(response))
        else:
            message = "Data: {!r}".format(hexlify(response))
        AccessProtocolError.__init__(self, message)


class UnexpectedResponseError(AccessProtocolError):
    """
    Raised when a different Response is received than expected.
    """

    pass


class UnexpectedBLEMessageError(AccessProtocolError):
    """
    Raised when a different ble message is received than expected.
    """

    def __init__(
        self, message: str = "", header: int | None = None, id: int | None = None
    ):
        if header is not None:
            message += ", received header: 0x{:02x}".format(header)
        if id is not None:
            message += ", received id: 0x{:02x}".format(id)
        AccessProtocolError.__init__(self, message)


class UnexpectedCommandError(AccessProtocolError):
    """
    Raised when a different command is received than expected.
    """

    pass


class VersionError(AccessProtocolError):
    """
    Raised when the requested version is not supported.
    """

    pass


class CreateCommandError(AccessProtocolError):
    pass


class CreateResponseError(AccessProtocolError):
    pass


class MessageTooLongError(AccessProtocolError):
    """
    Raised when the received command is too long.
    See 8.3 of the Aliro Spec.
    """

    pass


class InvalidCommandError(AccessProtocolError):
    """
    Raised when the received command is invalid.
    """

    def __init__(self, command: bytes) -> None:
        message = "command: {!r}".format(hexlify(command))
        super().__init__(message)


class InvalidCLAError(InvalidCommandError):
    """
    Raised when the received command has an invalid CLA.
    """

    pass


class InvalidINSError(InvalidCommandError):
    """
    Raised when the received command has an invalid INS.
    """

    pass


class InvalidParameterError(InvalidCommandError):
    """
    Raised when the received command has an invalid Paramenter (P1 or P2).
    """

    pass


class InvalidLcError(InvalidCommandError):
    """
    Raised when the received command has an invalid LC.
    """

    pass


class InvalidLeError(InvalidCommandError):
    """
    Raised when the received command has an invalid Le.
    """

    pass


class InvalidCommandDataError(InvalidCommandError):
    """
    Raised when the received command has an invalid Data field.
    """

    def __init__(self, command: bytes, message: str | None = None) -> None:
        if message is not None:
            message += ", command: {!r}".format(hexlify(command))
        else:
            message = "command: {!r}".format(hexlify(command))
        AccessProtocolError.__init__(self, message)


class InvalidAIDError(InvalidCommandDataError):
    """
    Raised when a command with an invalid AID is received.
    """

    def __init__(self, command: bytes, aid: bytes) -> None:
        message = "invalid AID received: {!r}, expected one of: {!r}".format(
            aid, [EXPEDITED_PHASE_AID, STEPUP_PHASE_AID]
        )
        message += ", full command: {!r}".format(hexlify(command))
        AccessProtocolError.__init__(self, message)


class InvalidResponseError(AccessProtocolError):
    """
    Raised when the received response is invalid.
    """

    def __init__(self, response: bytes):
        message = "response: {!r}".format(hexlify(response))
        super().__init__(message)


class InvalidStatusError(InvalidResponseError):
    """
    Raised when the received Response has an invalid status.
    """

    def __init__(self, response: bytes, status: int, additional_message: str = ""):
        self.status = status
        message = "invalid status found: 0x{:04x}, complete response: {!r}".format(
            status, hexlify(response)
        )
        if additional_message != "":
            message += ", " + additional_message
        AccessProtocolError.__init__(self, message)


class InvalidResponseDataError(InvalidResponseError):
    """
    Raised when the received Response has an invalid data.
    """

    def __init__(self, response: bytes, other_info: str = ""):
        if other_info != "":
            message = "{}, response: {!r}".format(other_info, hexlify(response))
        else:
            message = "response: {!r}".format(hexlify(response))
        AccessProtocolError.__init__(self, message)
