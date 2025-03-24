"""Utecio Exceptions"""

### Base Errors
class UtecBleDeviceError(Exception):
    """Base exception for Device Errors"""
    pass

class UtecBleError(Exception):
    """Base exception for Utec BLE operations."""
    pass

class UtecApiError(Exception):
    """Base Exception for Utec API errors"""
    pass

class UtecEncryptionError(Exception):
    """Base Error for encrtyption Errors"""
    pass

### Device Errors
class UtecBleDeviceBusyError(UtecBleDeviceError):
    """Error for when device is busy"""
    pass

class DeviceNotAvailable(UtecBleDeviceError):
    """Device not visible on Bluetooth Network."""
    pass

class UtecConnectionError(UtecBleError):
    """Error when connecting to the device."""
    pass

class UtecAuthError(UtecBleError):
    """Error during authentication."""
    pass

### Bluetooth Errors
class UtecBleNotFoundError(UtecBleError):
    """Bluetooth Device Not Found"""
    pass

class UtecProtocolError(UtecBleError):
    """Ble Protocol errors"""
    pass

### API Errors
class InvalidResponse(UtecApiError):
    """Unknown response from UTEC servers."""
    pass

class InvalidCredentials(UtecApiError):
    """Could not login to UTEC servers."""
    pass

class UtecTimeoutError(UtecApiError):
    """API Timed Out"""
    pass
