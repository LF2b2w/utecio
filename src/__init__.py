"""
Utec IO - Python library for interfacing with Utec smart devices.

This package provides an interface for communicating with Utec smart locks and other
Bluetooth devices through both BLE (local) and cloud connections.
"""

import logging
from typing import Optional, Dict, Any

from aiohttp import ClientSession

# Package metadata
__version__ = "1.0.0"
__author__ = "Utec IO Contributors"

# Configure package-level logger
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

# Create console handler if no handlers exist
if not logger.handlers:
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(
        logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    )
    logger.addHandler(console_handler)

# Import key components for easier access
from .exceptions import (
    UtecApiError,
    UtecBleError,
    UtecConnectionError,
    UtecEncryptionError,
    UtecAuthError,
    UtecProtocolError
)

from .const import (
    LOCK_MODE,
    BOLT_STATUS,
    BATTERY_LEVEL,
    DeviceKeyUUID,
    DeviceServiceUUID,
    BLECommandCode,
    BleResponseCode
)

# Import main functionality
from .ble.device import UtecBleDevice, UtecBleRequest, UtecBleResponse, get_device_key
from .ble.lock import UtecBleLock
from .cloud import UtecApiClient, UtecCloud

# Utility functions
from .util import (
    date_from_4bytes,
    bytes_to_int2,
    bytes_to_int4,
    bytes_to_ascii,
    int_to_bytes,
    decode_password
)

# Setup function to create a lock
def setup(
    mac_address: str,
    device_id: Optional[str] = None,
    password: Optional[str] = None,
    name: Optional[str] = None,
    cloud_config: Optional[Dict[str, Any]] = None,
    log_level: int = logging.INFO
) -> UtecBleLock:
    """Set up a Utec lock device with the specified parameters.

    Args:
        mac_address: The MAC address of the lock
        device_id: The device ID/UID (optional)
        password: The device password (optional)
        name: A friendly name for the device (optional)
        cloud_config: Configuration for cloud connection (optional)
        log_level: Logging level for this device

    Returns:
        A configured UtecLock instance
    """
    # Set package logger level
    logger.setLevel(log_level)

    # Create and return a lock instance
    lock = UtecBleLock(
        mac_address=mac_address,
        device_id=device_id,
        password=password,
        name=name,
    )

    if cloud_config:
        cloud = UtecCloud(cloud_config)
        return discover_devices_api(cloud)

    return lock

# Convenience function to discover nearby devices
async def discover_devices_ble(timeout: int = 5):
    """Discover nearby Utec BLE devices.

    Args:
        timeout: Discovery timeout in seconds

    Returns:
        List of discovered devices
    """
    from .api import discover_utec_devices
    return await discover_utec_devices(timeout)

async def discover_devices_api(cloud):
    """Discover devices via API"""
    await UtecCloud.connect(cloud)
    logger.info("Successfully connected to Utec cloud")

        # Get all BLE devices
    ble_devices = await cloud.get_ble_devices()
    logger.info(f"Found {len(ble_devices)} BLE-capable devices")

        # Process each device
    for device in ble_devices:
        logger.info(f"\nDevice: {device.name}")
        logger.info(f"MAC Address: {device.mac_address}")
        logger.info(f"UID: {device.uid}")

            # Get additional cloud details
        device_details = await cloud.get_device_details(device.id)
        if device_details:
            logger.info("Device details:")
            logger.info(f"  Model: {device_details.get('model', 'Unknown')}")
            logger.info(f"  Firmware: {device_details.get('firmware_version', 'Unknown')}")
            logger.info(f"  Battery: {device_details.get('battery_level', 'Unknown')}%")

                # Optional: Get recent activity
            history = await cloud.get_device_history(device.id, limit=3)
            if history:
                logger.info("Recent activity:")
                for event in history:
                    logger.info(f"  {event.get('time', 'Unknown')}: {event.get('action', 'Unknown')}")

            # Connect to the device via Bluetooth
        try:
            logger.info(f"Connecting to {device.name} via BLE...")
            await device.connect()

                # Get real-time device status
            await device.get_lock_status()
            logger.info(f"Current lock mode: {device.lock_mode}")
            logger.info(f"Current battery: {device.battery}%")

                # Disconnect when done
            await device.disconnect()
            logger.info("Disconnected from device")

        except UtecConnectionError as e:
            logger.error(f"Failed to connect to device: {e}")

        except UtecAuthError as e:
            logger.error(f"Authentication failed: {e}")
        except UtecApiError as e:
            logger.error(f"API error: {e}")
        except Exception as e:
            logger.error(f"Unexpected error: {e}")
        finally:
        # Always clean up resources
            await cloud.close()
            logger.info("Cloud client closed")
