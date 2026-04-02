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
import datetime

from aliro_actuator.access_document.utility import Utility

################################################################################
class ValidityInfo(object):
    '''Aliro Validity Information.'''

    SIGNED_LABEL = "1"
    '''The label for the Signed field.'''

    VALID_FROM_LABEL = "2"
    '''The label for the Valid From field.'''

    VALID_UNTIL_LABEL = "3"
    '''The label for the Valid Unit field.'''

    EXPECTED_UPDATED_LABEL = "4"
    '''The label for the Expected Update field.'''

    VALIDITY_ITERATION_LABEL = "5"
    '''The label for the optional Validity Iteration field.'''

    TDATE_STR_LEN = 20
    '''The length of a tdate string.'''

    ############################################################################
    def __init__(self) -> None:
        self.__signed : str = "" # CBOR tdate
        self.__valid_from : str = "" # CBOR tdate
        self.__valid_until : str = "" # CBOR tdate
        self.__expected_update : str = ""  # CBOR tdate
        self.__validity_iteration : int = -1 # Initialize to an invalid validity iteration because it is optional.

    ############################################################################
    @property
    def signed(self) -> str:
        '''Get the timestamp at which the MSO signature was created.'''
        return self.__signed

    @signed.setter
    def signed(self, val : str | int | float | datetime.date | datetime.datetime) -> None:
        '''Set the timestamp at which the MSO signature was created.'''
        if isinstance(val, str):
            self.__signed = val
        else:
            self.__signed = Utility.time_val_to_tdate(val)

    ############################################################################
    @property
    def valid_from(self) -> str:
        '''Get the timestamp before which the MSO is not yet valid.'''
        return self.__valid_from

    @valid_from.setter
    def valid_from(self, val : str | int | float | datetime.date | datetime.datetime) -> None:
        '''Set the timestamp before which the MSO is not yet valid.'''
        if isinstance(val, str):
            self.__valid_from = val
        else:
            self.__valid_from = Utility.time_val_to_tdate(val)

    ############################################################################
    @property
    def valid_until(self) -> str:
        '''Get the timestamp after which the MSO is no longer valid.'''
        return self.__valid_until

    @valid_until.setter
    def valid_until(self, val : str | int | float | datetime.date | datetime.datetime) -> None:
        '''Set the timestamp after which the MSO is no longer valid.'''
        if isinstance(val, str):
            self.__valid_until = val
        else:
            self.__valid_until = Utility.time_val_to_tdate(val)

    ############################################################################
    @property
    def expected_update(self) -> str:
        '''Get the timestamp at which the issuing authority infrastructure
           expects to re-sign the MSO (and potentially update data elements).'''
        return self.__expected_update

    @expected_update.setter
    def expected_update(self, val : int | float | datetime.date | datetime.datetime) -> None:
        '''Set the timestamp at which the issuing authority infrastructure
           expects to re-sign the MSO (and potentially update data elements).'''
        self.__expected_update = Utility.time_val_to_tdate(val)

    ############################################################################
    @property
    def validity_iteration(self) -> int:
        '''Get the validity iteration.'''
        return self.__validity_iteration

    @validity_iteration.setter
    def validity_iteration(self, val : int) -> None:
        '''Set the validity iteration.'''
        assert(isinstance(val, int))
        if (val < 0):
            val = -1 # An invalid validity iteration.
        self.__validity_iteration = int(val)

    ############################################################################
    def is_valid(self) -> bool:
        '''Returns True if the ValidityInfo contains valid fields,
           otherwise returns False.'''

        # Verify the Signed field.
        if (len(self.__signed) != 20):
            return False

        # Verify the Valid From field.
        if (len(self.__valid_from) != 20):
            return False

        # Verify the Valid Until field.
        if (len(self.__valid_until) != 20):
            return False

        # The Expected Update field is an optional CBOR tdate string.
        if (self.__expected_update is not None):
            # Verify the Expected Update is of type string.
            if (not isinstance(self.__expected_update, str)):
                return False
            # Verify the Expected Update is an empty string or has a length of twenty "YYYY-mm-ddTHH:MM:SSZ".
            if (not ((len(self.__expected_update) == 0) or (len(self.__expected_update) == 20))):
                return False

        # The Validity Iteration field is optional.
        if (not isinstance(self.__validity_iteration, int)):
            return False

        return True

    ############################################################################
    def to_dict(self, validate=True) -> dict:
        '''Convert the ValidityInfo to a dictionary.'''
        if validate and not self.is_valid():
            return None

        validity_info_dict = {}
        cbor_tag_tdate = 0

        # Encode the Signed field.
        validity_info_dict[ValidityInfo.SIGNED_LABEL] = cbor2.CBORTag(cbor_tag_tdate, str(self.__signed))

        # Encode the Valid From field.
        validity_info_dict[ValidityInfo.VALID_FROM_LABEL] = cbor2.CBORTag(cbor_tag_tdate, str(self.__valid_from))

        # Encode the Valid Until field.
        validity_info_dict[ValidityInfo.VALID_UNTIL_LABEL] = cbor2.CBORTag(cbor_tag_tdate, str(self.__valid_until))

        # Encode the optional Expected Update field.
        if (self.__expected_update is not None) and (len(self.__expected_update) > 0):
            validity_info_dict[ValidityInfo.EXPECTED_UPDATED_LABEL] = cbor2.CBORTag(cbor_tag_tdate, str(self.__expected_update))

        # Encode the Validity Iteration.
        if (self.__validity_iteration >= 0):
            validity_info_dict[ValidityInfo.VALIDITY_ITERATION_LABEL] = int(self.__validity_iteration)

        return validity_info_dict

    ############################################################################
    def from_dict(self, validity_info_dict: dict) -> bool:
        signed = validity_info_dict.get(ValidityInfo.SIGNED_LABEL)
        if (signed is None) or (not isinstance(signed, datetime.datetime)):
            return False
        signed = signed.replace(tzinfo=None)
        self.__signed = Utility.time_val_to_tdate(signed)

        valid_from = validity_info_dict.get(ValidityInfo.VALID_FROM_LABEL)
        if (valid_from is None) or (not isinstance(valid_from, datetime.datetime)):
            return False
        valid_from = valid_from.replace(tzinfo=None)
        self.__valid_from = Utility.time_val_to_tdate(valid_from)

        valid_until = validity_info_dict.get(ValidityInfo.VALID_UNTIL_LABEL)
        if (valid_until is None) or (not isinstance(valid_until, datetime.datetime)):
            return False
        valid_until = valid_until.replace(tzinfo=None)
        self.__valid_until = Utility.time_val_to_tdate(valid_until)

        expected_update = validity_info_dict.get(ValidityInfo.EXPECTED_UPDATED_LABEL)
        if ((expected_update is not None) and isinstance(expected_update, datetime.datetime)):
            expected_update = expected_update.replace(tzinfo=None)
            self.__expected_update = Utility.time_val_to_tdate(expected_update)

        validity_iteration = validity_info_dict.get(ValidityInfo.VALIDITY_ITERATION_LABEL)
        if ((validity_iteration is not None) and validity_iteration >= 0):
            self.__validity_iteration = validity_iteration

        return self.is_valid()

    ############################################################################
    def to_cbor(self, validate=True) -> bytes:
        '''Convert the ValidityInfo to CBOR.'''
        validity_info_dict = self.to_dict(validate)
        if validity_info_dict is None:
            return None
        return cbor2.dumps(validity_info_dict)
