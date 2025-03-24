class UtecBleNotFoundError(Exception):
    pass


class UtecBleError(Exception):
    pass


class UtecBleDeviceError(Exception):
    pass


class UtecBleDeviceBusyError(Exception):
    pass

class DeviceNotAvailable(Exception):
    """Device not visible on Bluetooth Network."""
