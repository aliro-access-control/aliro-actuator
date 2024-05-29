import ucitool.base_uci.helpers.uci_helper as uci

from aliro_actuator.hw_driver.murata_driver.uwb_driver import MurataUWBDriver


def main():
    driver = MurataUWBDriver("/dev/ttyUSB0", 576000)
    driver.uci_initialize(
        session_id=0,
        dev_role=uci.APP_CFG.DEVICE_ROLE.RESPONDER,
        dev_type=uci.APP_CFG.DEVICE_TYPE.CONTROLEE,
    )

    print(f"Pulse Shape Combo: {driver.get_pulse_shape_combination()}")
    print(f"Channel Bitmask: {driver.get_channel_bitmask()}")


if __name__ == "__main__":
    main()
