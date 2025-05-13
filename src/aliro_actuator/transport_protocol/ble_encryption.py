from __future__ import annotations

from aliro_actuator import Global
from aliro_actuator.access_protocol.encryption import DeviceType, EncryptionEngine
from aliro_actuator.trust_framework.key import derive_key


def get_ble_encryption(
    device_type: DeviceType,
    ble_sk: bytes,
    selected_version: int,
    supported_versions: list[int],
) -> EncryptionEngine:
    Global.logger.info

    supported_versions_bytearray = bytearray()
    for version in supported_versions:
        supported_versions_bytearray.extend(version.to_bytes(2, "big"))
    supported_versions_bytes = bytes(supported_versions_bytearray)

    salt = supported_versions_bytes + selected_version.to_bytes(2, "big")
    ble_sk_reader = derive_key(ble_sk, "BleSKReader".encode("utf-8"), 32, salt)
    ble_sk_device = derive_key(ble_sk, "BleSKDevice".encode("utf-8"), 32, salt)
    return EncryptionEngine(device_type, ble_sk_reader, ble_sk_device)
