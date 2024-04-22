def change_endianness(data: bytes) -> bytes:
    result = bytearray(data)
    result.reverse()
    return bytes(result)
