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

    pass


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

    pass


class FSCIError(MurataError):
    """
    Raised when an error in the FSCI protocol is found.
    """

    pass


class STXError(MurataError):
    """
    Raised when an message with an invalid STX is received.
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
