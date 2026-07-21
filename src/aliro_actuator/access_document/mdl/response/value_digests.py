#
# Copyright (c) 2024 Aliro Authors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

import cbor2
import copy

################################################################################
class ValueDigests(object):

    ############################################################################
    def __init__(self) -> None:
        self.__data : dict[str, dict[int, bytearray]] = {}

    ############################################################################
    @property
    def data(self) -> dict[str, dict[int, bytearray]]:
        '''Get the Value Digests.'''
        return self.__data

    ############################################################################
    def set(self, namespace : str, id : int, digest : bytes | bytearray) -> None:
        '''Set the Digest with the given ID within the given Namespace.'''
        assert(isinstance(namespace, str))
        assert(isinstance(id, int))
        assert(isinstance(digest, (bytes, bytearray)))
        assert(len(namespace) > 0)
        assert(len(digest) > 0)
        if namespace in self.__data:
            self.__data[namespace][id] = bytearray(digest)
        else:
            self.__data[namespace] = {id : bytearray(digest)}

    ############################################################################
    def is_valid(self) -> bool:
        '''Returns True if the ValueDigests contains valid fields,
           otherwise returns False.'''
        # Verify the Data field.
        if (type(self.__data) is not dict) or (len(self.__data) == 0):
            return False
        return True

    ############################################################################
    def to_dict(self, validate=True) -> dict:
        '''Convert the ValueDigests to a dictionary.'''
        if validate and not self.is_valid():
            return None
        return copy.deepcopy(self.__data)

    ############################################################################
    def from_dict(self, copy_dict: dict) -> bool:
        '''Convert the dictionary to ValueDigests.'''
        if (copy_dict is not None):
            self.__data = copy.deepcopy(copy_dict)

        return self.is_valid()

    ############################################################################
    def to_cbor(self, validate=True) -> bytes:
        '''Convert the ValueDigests to CBOR.'''
        value_digests_dict = self.to_dict(validate)
        if value_digests_dict is None:
            return None
        return cbor2.dumps(value_digests_dict)

    ############################################################################
    def from_cbor(self, cbor_data : (bytes | bytearray)) -> bool:
        '''Parse CBOR to populate the ValueDigests.'''
        assert(isinstance(cbor_data, (bytes, bytearray)))
        return self.from_dict(cbor2.loads(cbor_data))