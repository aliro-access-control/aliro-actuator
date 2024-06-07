from hashlib import sha1

from aliro_actuator.trust_framework.key import PublicKey


def get_key_slot(key: PublicKey) -> bytes:
    return sha1(key.as_bytes()).digest()[:8]
