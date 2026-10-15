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

from .device_request import DeviceRequest
from .doc_request import DocRequest

from aliro_actuator.access_document.mdl.common.doc_types import DocTypes
from aliro_actuator.access_document.mdl.common.issuer_namespaces import IssuerNamespaces

################################################################################
class RequestElement(object):
    '''Aliro Device Request Element.'''

    ############################################################################
    def __init__(self, data_element_id : str = "", intent_to_retain : bool = False) -> None:
        self.__data_element_id : str = data_element_id
        self.__intent_to_retain : bool = intent_to_retain

    ############################################################################
    @property
    def data_element_id(self) -> str:
        '''Get the Data Element Identifier.'''
        return self.__data_element_id

    @data_element_id.setter
    def data_element_id(self, val : str) -> None:
        '''Set the Data Element Identifier.'''
        assert(isinstance(val, str))
        assert(len(val) > 0)
        self.__data_element_id = str(val)

    ############################################################################
    @property
    def intent_to_retain(self) -> bool:
        '''Get the Intent-to-Retain.'''
        return self.__intent_to_retain

    @intent_to_retain.setter
    def intent_to_retain(self, val : bool) -> None:
        '''Set the Intent-to-Retain.'''
        assert(isinstance(val, bool))
        self.__intent_to_retain = bool(val)


################################################################################
class DeviceRequestBuilder(object):
    '''Aliro Device Request Builder.'''

    ############################################################################
    @staticmethod
    def build(
        access_data_elements : list[RequestElement],
        revocation_data_elements : list[RequestElement]) -> DeviceRequest:
        '''Build a Device Request from the given request elements.'''

        # Verify input parameters.
        if (access_data_elements is not None):
            assert(isinstance(access_data_elements, list))
        if (revocation_data_elements is not None):
            assert(isinstance(revocation_data_elements, list))

        # Create the Device Request to populate with
        # data from the given request elements.
        device_request = DeviceRequest()

        # Setup the Access Doc request.
        if len(access_data_elements) > 0:
            access_doc_request = DocRequest()
            access_doc_request.items_request.doc_type = DocTypes.ALIRO_ACCESS
            device_request.doc_requests.append(access_doc_request)

        # Specify which Access Docs to request.
        for access_request in access_data_elements:
            access_doc_request.items_request.namespaces.set(
                IssuerNamespaces.ALIRO_ACCESS,
                access_request.data_element_id,
                access_request.intent_to_retain)

        # Setup the Revocation request.
        if (len(revocation_data_elements) > 0):
            revocation_doc_request = DocRequest()
            revocation_doc_request.items_request.doc_type = DocTypes.ALIRO_REVOCATION
            device_request.doc_requests.append(revocation_doc_request)

        # Specify which Revocation Docs to request.
        for revocation_request in revocation_data_elements:
            revocation_doc_request.items_request.namespaces.set(
                IssuerNamespaces.ALIRO_REVOCATION,
                revocation_request.data_element_id,
                revocation_request.intent_to_retain)

        return device_request
