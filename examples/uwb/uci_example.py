import asyncio

import ucitool.base_uci.helpers.uci_helper as uci

from aliro_actuator.hw_driver.murata_driver.uwb_driver import MurataUWBDriver


async def main():
    driver = MurataUWBDriver("/dev/ttyUSB0", 576000)
    await driver.uci_initialize(
        session_id=0,
        dev_role=uci.APP_CFG.DEVICE_ROLE.RESPONDER,
        dev_type=uci.APP_CFG.DEVICE_TYPE.CONTROLEE,
    )

    print(f"pulseshape_combo: {hex(driver.get_pulse_shape_combination())}")
    print(f"channel_bitmask: {hex(driver.get_channel_bitmask())}")
    print(f"slot bitmask: {hex(driver.get_slot_bitmask())}")
    print(f"sync_code_index_bitmask: {hex(driver.get_sync_code_bitmask())}")
    print(f"hopping_config_bitmask = {hex(driver.get_hopping_config_bitmask())}")


if __name__ == "__main__":
    asyncio.run(main())
