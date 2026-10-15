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

from aliro_actuator.access_document.aliro.common.extension_data import ExtensionData

################################################################################
class MultipleUsersExtensionData(ExtensionData):
    '''Multiple Users Extension Data.'''

    TIMEOUT_SECONDS_LABEL = 0
    '''The label for the Timeout Seconds field.'''

    ACCESS_POINTS_LABEL = 1
    '''The label for the Access Points field.'''

    REQUIRED_ACCESS_POINTS_LABEL = 2
    '''The label for the Required Access Points field.'''

    USER_LIMIT_LABEL = 3
    '''The label for the User Limit field.'''


    TIMEOUT_SECONDS_MIN = 10
    '''The minimum timeout in seconds.'''

    TIMEOUT_SECONDS_MAX = 60
    '''The maximum timeout in seconds.'''

    TIMEOUT_SECONDS_DEFAULT = 30
    '''The default timeout in seconds.'''


    ACCESS_POINTS_MIN = 1
    '''The minimum number of access points.'''

    ACCESS_POINTS_MAX = 3
    '''The maximum number of access points.'''

    ACCESS_POINTS_DEFAULT = 1
    '''The default number of access points.'''


    REQUIRED_ACCESS_POINTS_MIN = 2
    '''The minimum required total number of points for access.'''

    REQUIRED_ACCESS_POINTS_MAX = 10
    '''The minimum required total number of points for access.'''

    REQUIRED_ACCESS_POINTS_DEFAULT = 2
    '''The default required total number of points for access.'''


    USER_LIMIT_MIN = 2
    '''The minimum number of users who may contribute points for access.'''

    USER_LIMIT_MAX = 4
    '''The maximum number of users who may contribute points for access.'''

    USER_LIMIT_DEFAULT = 2
    '''The default number of users who may contribute points for access.'''

    ############################################################################
    def __init__(self) -> None:
        self.__timeout_seconds : int = MultipleUsersExtensionData.TIMEOUT_SECONDS_DEFAULT
        self.__access_points : int = MultipleUsersExtensionData.ACCESS_POINTS_DEFAULT
        self.__required_access_points : int = MultipleUsersExtensionData.REQUIRED_ACCESS_POINTS_DEFAULT
        self.__user_limit : int = MultipleUsersExtensionData.USER_LIMIT_DEFAULT
        return

    ############################################################################
    @property
    def timeout_seconds(self) -> int:
        '''Get the timeout in seconds.'''
        return self.__timeout_seconds

    @timeout_seconds.setter
    def timeout_seconds(self, val : int) -> None:
        '''Set the timeout in seconds.'''
        assert(isinstance(val, int))
        if (val < MultipleUsersExtensionData.TIMEOUT_SECONDS_MIN):
            self.__timeout_seconds = int(MultipleUsersExtensionData.TIMEOUT_SECONDS_MIN)
        elif (val > MultipleUsersExtensionData.TIMEOUT_SECONDS_MAX):
            self.__timeout_seconds = int(MultipleUsersExtensionData.TIMEOUT_SECONDS_MAX)
        else:
            self.__timeout_seconds = int(val)

    ############################################################################
    @property
    def access_points(self) -> int:
        '''Get the number of access points.'''
        return self.__access_points

    @access_points.setter
    def access_points(self, val : int) -> None:
        '''Set the number of access points.'''
        assert(isinstance(val, int))
        if (val < MultipleUsersExtensionData.ACCESS_POINTS_MIN):
            self.__access_points = int(MultipleUsersExtensionData.ACCESS_POINTS_MIN)
        elif (val > MultipleUsersExtensionData.ACCESS_POINTS_MAX):
            self.__access_points = int(MultipleUsersExtensionData.ACCESS_POINTS_MAX)
        else:
            self.__access_points = int(val)

    ############################################################################
    @property
    def required_access_points(self) -> int:
        '''Get the required total number of points for access.'''
        return self.__required_access_points

    @required_access_points.setter
    def required_access_points(self, val : int) -> None:
        '''Set the required total number of points for access.'''
        assert(isinstance(val, int))
        if (val < MultipleUsersExtensionData.REQUIRED_ACCESS_POINTS_MIN):
            self.__required_access_points = int(MultipleUsersExtensionData.REQUIRED_ACCESS_POINTS_MIN)
        elif (val > MultipleUsersExtensionData.REQUIRED_ACCESS_POINTS_MAX):
            self.__required_access_points = int(MultipleUsersExtensionData.REQUIRED_ACCESS_POINTS_MAX)
        else:
            self.__required_access_points = int(val)

    ############################################################################
    @property
    def user_limit(self) -> int:
        '''Get the number of users who may contribute points for access.'''
        return self.__user_limit

    @user_limit.setter
    def user_limit(self, val : int) -> None:
        '''Set the number of users who may contribute points for access.'''
        assert(isinstance(val, int))
        if (val < MultipleUsersExtensionData.USER_LIMIT_MIN):
            self.__user_limit = int(MultipleUsersExtensionData.USER_LIMIT_MIN)
        elif (val > MultipleUsersExtensionData.USER_LIMIT_MAX):
            self.__user_limit = int(MultipleUsersExtensionData.USER_LIMIT_MAX)
        else:
            self.__user_limit = int(val)

    ############################################################################
    def is_valid(self) -> bool:
        '''Returns True if the MultipleUsersExtensionData contains valid fields,
           otherwise returns False.'''

        # Verify the Timeout in Seconds.
        if ((self.timeout_seconds is None) or \
            (not isinstance(self.timeout_seconds, int))) or \
            (self.timeout_seconds < MultipleUsersExtensionData.TIMEOUT_SECONDS_MIN) or \
            (self.timeout_seconds > MultipleUsersExtensionData.TIMEOUT_SECONDS_MAX):
            return False

        # Verify the Access Points.
        if ((self.access_points is None) or \
            (not isinstance(self.access_points, int))) or \
            (self.access_points < MultipleUsersExtensionData.ACCESS_POINTS_MIN) or \
            (self.access_points > MultipleUsersExtensionData.ACCESS_POINTS_MAX):
            return False

        # Verify the Required Access Points.
        if ((self.required_access_points is None) or \
            (not isinstance(self.required_access_points, int))) or \
            (self.required_access_points < MultipleUsersExtensionData.REQUIRED_ACCESS_POINTS_MIN) or \
            (self.required_access_points > MultipleUsersExtensionData.REQUIRED_ACCESS_POINTS_MAX):
            return False

        # Verify the User Limit.
        if ((self.user_limit is None) or \
            (not isinstance(self.user_limit, int))) or \
            (self.user_limit < MultipleUsersExtensionData.USER_LIMIT_MIN) or \
            (self.user_limit > MultipleUsersExtensionData.USER_LIMIT_MAX):
            return False

        return True

    ############################################################################
    def to_bytes(self, validate=True) -> bytes | None:
        '''Convert the MultipleUsersExtensionData to a byte array.'''
        if validate and not self.is_valid():
            return None

        extension_data_dict = {}

        # Encode the Timeout in Seconds.
        extension_data_dict[MultipleUsersExtensionData.TIMEOUT_SECONDS_LABEL] = int(self.timeout_seconds)

        # Encode the Access Points.
        extension_data_dict[MultipleUsersExtensionData.ACCESS_POINTS_LABEL] = int(self.access_points)

        # Encode the Required Access Points.
        extension_data_dict[MultipleUsersExtensionData.REQUIRED_ACCESS_POINTS_LABEL] = int(self.required_access_points)

        # Encode the User Limit.
        extension_data_dict[MultipleUsersExtensionData.USER_LIMIT_LABEL] = int(self.user_limit)

        return cbor2.dumps(extension_data_dict)
