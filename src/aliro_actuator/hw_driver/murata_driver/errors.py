from binascii import hexlify


class MurataError(Exception):
    """
    Parent class of all errors related to the murata driver.
    """

    pass


class NoResponseError(MurataError):
    """
    Raised when no response is received (but one is expected).
    """

    def __init__(self) -> None:
        super().__init__("No response received")


class UnexpectedResponseError(MurataError):
    """
    Raised when a response is received, but the response is different from the expected
    response.
    """

    pass


class ErrorReturnedError(MurataError):
    """
    Raised when a response is received, but the response contains an error.
    """

    def __init__(self, error_code: int, expected: list[int] | None = None) -> None:
        message = "Error returned: {:x}".format(error_code)
        self.error_code = error_code
        if expected is not None:
            expected_str = ""
            for expected_bytes in expected:
                expected_str += "{:x}, ".format(expected_bytes)
            message += " (expected: {})".format(expected_str)
        super().__init__(message)


class STXError(MurataError):
    """
    Raised when an message with an invalid STX is received.
    """

    def __init__(self) -> None:
        super().__init__("Invalid STX received")


class FSCIError(MurataError):
    """
    Raised when an error in the FSCI protocol is found.
    """

    pass


class GATTError(MurataError):
    """
    Raised when an error in the GATT layer is found.
    """

    pass


class InvalidChecksumError(FSCIError):
    """
    Raised when a message contains an invalid checksum.
    """

    def __init__(self, expected: bytes, actual: bytes) -> None:
        message = "expected: {!r}, actual: {!r}".format(
            hexlify(expected), hexlify(actual)
        )
        super().__init__(message)


class DeviceDisconnectedError(MurataError):
    """
    Raised when a device is disconnected.
    """

    pass
