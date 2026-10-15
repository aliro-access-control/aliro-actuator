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

import datetime

class Utility(object):
    BYTE_ORDER = 'big'
    '''The endian for serializing and deserializing values.'''

    ############################################################################
    @staticmethod
    def time_val_to_seconds(val : int | float | datetime.date | datetime.datetime) -> int:
        '''Convert the date / time to seconds since Unix epoch.'''
        assert isinstance(val, (int, float, datetime.date, datetime.datetime))
        if isinstance(val, (int, float)):
            t = int(val)
        elif type(val) is datetime.datetime:
            t = int(val.timestamp())
        elif type(val) is datetime.date:
            t = int(datetime.datetime(year=val.year, month=val.month, day=val.day).timestamp())
        else:
            raise TypeError

        if t < 0:
            t = int(0)
        return t

    ############################################################################
    @staticmethod
    def time_val_to_tdate(val : int | float | datetime.date | datetime.datetime, isUtc: bool = True) -> str:
        '''
            Convert the date / time to tdate with format "YYYY-mm-ddTHH:MM:SSZ".
                val: value of time data to be converted to tdate
                isUtc: if true, incoming data is already UTC. If false, data will be converted
                       from local timezone to UTC.
        '''
        assert isinstance(val, (int, float, datetime.date, datetime.datetime))
        if isinstance(val, (int, float)):
            dt = datetime.datetime.fromtimestamp(val)
        elif type(val) is datetime.datetime:
            dt = val
        elif type(val) is datetime.date:
            dt = datetime.datetime(year=val.year, month=val.month, day=val.day)
        else:
            raise TypeError

        if isUtc:
            dt = dt.replace(tzinfo=datetime.timezone.utc)
        else:
            dt = dt.astimezone(datetime.timezone.utc)

        return dt.isoformat('T', 'seconds').replace('+00:00', 'Z')

    ############################################################################
    @staticmethod
    def tdate_to_datetime(val: str) -> datetime.datetime:
        return datetime.datetime.strptime(val, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=datetime.timezone.utc)

    ############################################################################
    @staticmethod
    def uint_to_bytes(value : int, byteorder='big') -> bytes:
        '''
        Convert a non-negative integer to an array of bytes,
        using the minimum number of bytes.
        '''
        assert isinstance(value, int)
        if (value < 0):
            return None
        length = 1
        mask = 0xFF
        while value > mask:
            mask = (mask << 8) | 0xFF
            length += 1
        return value.to_bytes(length, byteorder=byteorder, signed=False)

    ############################################################################
    @staticmethod
    def int_to_bytes(value : int, byteorder='big') -> bytes:
        '''
        Convert an integer to an array of bytes,
        using the minimum number of bytes.
        '''
        assert isinstance(value, int)
        if (value >= 0):
            return Utility.uint_to_bytes(value, byteorder)
        else:
            if (value >= -128):
                length = 1
            elif (value >= -32768):
                length = 2
            elif (value >= -8388608):
                length = 3
            elif (value >= -2147483648):
                length = 4
            else:
                return None
            return value.to_bytes(length, byteorder=byteorder, signed=True)

    ############################################################################
    @staticmethod
    def bytes_to_hex_str(data : bytes | bytearray) -> str:
        '''Convert an array of bytes to a hex string.'''
        assert isinstance(data, (bytes, bytearray))
        return "".join("{:02X}".format(v) for v in data)

    ############################################################################
    @staticmethod
    def collection_bytes_to_hex_str(collection : dict | list) -> None:
        '''Recursively convert all arrays of bytes within a collection to hex strings.'''
        if isinstance(collection, dict):
            for key in collection.keys():
                val = collection[key]
                if isinstance(val, (bytes, bytearray)):
                    collection[key] = Utility.bytes_to_hex_str(val)
                if isinstance(val, (list, dict)):
                    Utility.collection_bytes_to_hex_str(val)
        if isinstance(collection, list):
            for index, val in enumerate(collection):
                if isinstance(val, (bytes, bytearray)):
                    collection[index] = Utility.bytes_to_hex_str(val)
                if isinstance(val, (list, dict)):
                    Utility.collection_bytes_to_hex_str(val)

    ############################################################################
    @staticmethod
    def dict_to_tlv(collection : dict) -> bytearray:
        '''Recursively convert a dictionary with integer or string keys to TLV.'''
        assert(isinstance(collection, dict))
        ba = bytearray()
        for key in collection.keys():
            val = collection[key]
            data = None
            if isinstance(val, dict):
                data = Utility.dict_to_tlv(val)
            elif isinstance(val, list):
                data = Utility.list_to_tlv(val)
            elif isinstance(val, (bytes, bytearray)):
                data = val
            elif isinstance(val, int):
                data = Utility.uint_to_bytes(val)
            elif isinstance(val, str):
                data = val.encode()
            elif isinstance(val, bool):
                data = bytearray()
                if val:
                    data.append(int(1))
                else:
                    data.append(int(0))
            else:
                # Data type is currently unsupported.
                return None

            if (data is None):
                return None

            # Encode the Tag.
            if isinstance(key, int):
                if (key >= 0):
                    ba.extend(Utility.uint_to_bytes(key))
                else:
                    ba.extend(Utility.int_to_bytes(key))
            elif isinstance(key, str):
                ba.extend(key.encode())
            else:
                return None

            # Encode the Length.
            data_len = len(data)
            if (data_len <= 127):
                ba.append(data_len)
            else:
                length_byte_count = 1
                length_mask = 0xFF
                while data_len > length_mask:
                    length_mask = (length_mask << 8) | 0xFF
                    length_byte_count += 1
                ba.append(0x80 | length_byte_count)
                ba.extend(Utility.uint_to_bytes(data_len))

            # Encode the Value.
            ba.extend(data)
        return ba

    ############################################################################
    @staticmethod
    def list_to_tlv(collection : list) -> bytearray:
        '''Recursively convert a list to TLV.'''
        assert(isinstance(collection, list))
        ba = bytearray()
        for index, item in enumerate(collection):
            if isinstance(item, dict):
                data = Utility.dict_to_tlv(item)
            elif isinstance(item, list):
                data = Utility.list_to_tlv(item)
            elif isinstance(item, (bytes, bytearray)):
                data = item
            elif isinstance(item, int):
                data = Utility.uint_to_bytes(item)
            elif isinstance(item, str):
                data = item.encode()
            elif isinstance(item, bool):
                data = bytearray()
                if item:
                    data.append(int(1))
                else:
                    data.append(int(0))
            else:
                # Data type is currently unsupported.
                return None

            if (data is None):
                return None

            # Encode the index as the Tag.
            ba.extend(Utility.uint_to_bytes(index))

            # Encode the Length.
            data_len = len(data)
            if (data_len <= 127):
                ba.append(data_len)
            else:
                length_byte_count = 1
                length_mask = 0xFF
                while data_len > length_mask:
                    length_mask = (length_mask << 8) | 0xFF
                    length_byte_count += 1
                ba.append(0x80 | length_byte_count)
                ba.extend(Utility.uint_to_bytes(data_len))

            # Encode the Value.
            ba.extend(data)
        return ba
