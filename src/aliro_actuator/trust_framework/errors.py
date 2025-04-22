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

from aliro_actuator import Global


class TrustFrameworkError(Exception):
    """
    Parent class of all errors related to the trust framework.
    """

    pass


class CertificateDecodingError(TrustFrameworkError):
    """
    Passed when a certificate cannot be decoded.
    """

    def __init__(self, certificate: bytes, message: str | None = None):
        error_message = "Error decoding certificate: {!r}".format(hexlify(certificate))
        if message is not None:
            error_message += ", {}".format(message)
        Global.logger.error(error_message)
        super().__init__(error_message)


class InvalidKeyFormatError(TrustFrameworkError):
    """
    Passed when a key has the wrong format.
    """

    pass


class MissingPublicKeyError(TrustFrameworkError):
    """
    Passed when initializing private key with 32 bytes data, and no public key.
    """

    pass


class InvalidKeyError(TrustFrameworkError):
    """
    Passed when a key is invalid.
    """

    def __init__(self, key: bytes, message: str | None = None):
        error_message = "Key not valid: {!r}".format(hexlify(key))
        if message is not None:
            error_message += ", {}".format(message)
        Global.logger.error(error_message)
        super().__init__(error_message)


class InvalidIdentifierError(TrustFrameworkError):
    """
    Passed when a identifier is invalid.
    """

    def __init__(self, identifier: bytes, message: str | None = None):
        error_message = "Identifier not valid: {!r}".format(hexlify(identifier))
        if message is not None:
            error_message += ", {}".format(message)
        Global.logger.error(error_message)
        super().__init__(error_message)


class KeyLookupFailed(TrustFrameworkError):
    pass
