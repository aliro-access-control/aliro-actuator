from binascii import hexlify

from Crypto.Cipher import AES

from aliro_actuator import Global


def dynamic_tag_generation(
    group_resolving_key: bytes,
    expiry_timestamp: bytes,
    advertising_address: bytes,
) -> bytes:
    plaintext = bytes.fromhex("000000000000") + advertising_address + expiry_timestamp
    cipher = AES.new(group_resolving_key, AES.MODE_ECB)
    ciphertext = cipher.encrypt(plaintext)
    Global.logger.debug("generated dynamic tag: {!r}".format(hexlify(ciphertext[:7])))

    return ciphertext[:7]
