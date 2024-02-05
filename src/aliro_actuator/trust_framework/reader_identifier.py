from aliro_actuator import READER_GROUP_ID_LENGTH, READER_ID_LENGTH
from aliro_actuator.trust_framework.errors import InvalidIdentifierError


class ReaderIdentifier:
    def __init__(self, identifier: bytes) -> None:
        if len(identifier) != READER_ID_LENGTH:
            raise InvalidIdentifierError(
                identifier,
                "invalid length ({}), should be {}".format(
                    len(identifier), READER_ID_LENGTH
                ),
            )
        self._identifier = identifier

    def get_group(self) -> bytes:
        return self._identifier[:READER_GROUP_ID_LENGTH]

    def get_group_sub(self) -> bytes:
        return self._identifier[READER_GROUP_ID_LENGTH:]

    def as_bytes(self) -> bytes:
        return self._identifier
