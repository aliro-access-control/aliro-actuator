import asyncio

import ucitool.base_uci.helpers.uci_helper as uci

from aliro_actuator.hw_driver.murata_driver.uwb_driver import MurataUWBDriver


async def main():
    driver = MurataUWBDriver("/dev/ttyUSB0", 230400)
    await driver.uci_initialize(
        dev_role=uci.APP_CFG.DEVICE_ROLE.RESPONDER,
        dev_type=uci.APP_CFG.DEVICE_TYPE.CONTROLEE,
    )

    await driver.get_capabilities()

    print(f"slot_bitmask: {hex(driver.slot_bitmask)}")
    print(f"sync_code_index_bitmask: {hex(driver.sync_code_index_bitmask)}")
    print(f"hopping_config_bitmask: {hex(driver.hopping_config_bitmask)}")
    print(f"channel_bitmask: {hex(driver.channel_bitmask)}")
    print(f"protocol_versions: {hex(driver.protocol_versions)}")
    print(f"uwb_config_id_support: {hex(driver.uwb_config_id_support)}")
    print(f"pulseshape_combo_support: {hex(driver.pulseshape_combo_support)}")


if __name__ == "__main__":
    asyncio.run(main())
