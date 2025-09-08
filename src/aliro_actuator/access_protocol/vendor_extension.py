from .tlv import TLV, TlvError

VENDOR_EXTENSION_TAG = 0x30
VENDOR_EXTENSION_VENDOR_ID_TAG = 0x04


class VendorExtension:
    def __init__(self, vendor_id: bytes, data: TLV):
        self.vendor_id = vendor_id
        self.data = data

    def __repr__(self):
        return f"<VendorExtension {self.vendor_id.hex()}: {self.data.to_print()}>"

    def to_bytes(self) -> bytes:
        vendor_bytes = TLV([(VENDOR_EXTENSION_VENDOR_ID_TAG, self.vendor_id)]).to_bytes()
        full_bytes = vendor_bytes + self.data.to_bytes()
        return TLV([(VENDOR_EXTENSION_TAG, full_bytes)]).to_bytes()

    @staticmethod
    def from_bytes(data: bytes):
        """
        Convert bytes to a list of VendorExtensions
        """
        list = TLV.from_bytes(data)
        root = list.get_all_of_tag(VENDOR_EXTENSION_TAG)
        ret = []
        for section in root:
            if section.data[0][0] != VENDOR_EXTENSION_VENDOR_ID_TAG:
                raise TlvError
            vendor_id = section.data[0][1]
            section.data = section.data[1:]
            ret.append(VendorExtension(vendor_id, section))

        return ret
