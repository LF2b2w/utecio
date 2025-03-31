"""Ble API for Utecio"""

import asyncio
import logging
from typing import Optional

from bleak import BleakClient, BleakScanner, AdvertisementData
from bleak.backends.device import BLEDevice

from src.ble.device import UtecBleDevice
from src.const import (
    UTEC_DEVICE_PREFIXES,
    UTEC_MANUFACTURER_IDS,
    DeviceServiceUUID
)

# Configure module logger
logger = logging.getLogger(__name__)



class UtecDeviceScanner:
    """Scanner for discovering Utec BLE devices."""

    def __init__(self):
        """Initialize the scanner."""
        self.discovered_devices: dict[str, dict] = {}
        self._scanner = BleakScanner()

    def _device_filter(self, device: BLEDevice, adv: AdvertisementData) -> bool:
        """Filter function to identify potential Utec devices.

        Args:
            device: The BLE device
            adv: Advertisement data

        Returns:
            True if device appears to be a Utec device
        """
        # Check for Utec service UUIDs
        for service_uuid in DeviceServiceUUID:
            if service_uuid.value.lower() in [str(uuid).lower() for uuid in adv.service_uuids]:
                return True

        # Check for known device name prefixes
        if device.name:
            for prefix in UTEC_DEVICE_PREFIXES:
                if device.name.upper().startswith(prefix):
                    return True

        # Check manufacturer data
        if adv.manufacturer_data:
            for mfr_id in UTEC_MANUFACTURER_IDS:
                if mfr_id in adv.manufacturer_data:
                    return True

        return False

    async def discover(self, timeout: float = 5.0) -> list[dict]:
        """Discover Utec BLE devices.

        Args:
            timeout: Scan timeout in seconds

        Returns:
            List of discovered devices with details
        """
        logger.info(f"Starting Utec device discovery (timeout: {timeout}s)")
        self.discovered_devices = {}

        def _device_found_callback(device: BLEDevice, adv_data: AdvertisementData):
            if self._device_filter(device, adv_data):
                self.discovered_devices[device.address] = {
                    "address": device.address,
                    "name": device.name or "Unknown",
                    "rssi": adv_data.rssi,
                    "service_uuids": adv_data.service_uuids,
                    "device": device
                }

        # Initialize scanner with callback directly in constructor
        self._scanner = BleakScanner(detection_callback=_device_found_callback)

        # Start scanner (callback already registered in constructor)
        await self._scanner.start()

        # Wait for specified timeout
        await asyncio.sleep(timeout)

        # Stop scanner
        await self._scanner.stop()

        logger.info(f"Discovery complete. Found {len(self.discovered_devices)} potential Utec devices")
        return list(self.discovered_devices.values())

    async def get_device_details(self, address: str, timeout: float = 5.0) -> Optional[dict]:
        """Get more details about a specific device by connecting to it.

        Args:
            address: Device MAC address
            timeout: Connection timeout in seconds

        Returns:
            Device details or None if connection fails
        """
        if address not in self.discovered_devices:
            logger.warning(f"Device {address} not in discovered devices")
            return None

        device_info = self.discovered_devices[address]
        device = device_info["device"]

        try:
            logger.debug(f"Connecting to {address} to get device details")
            async with BleakClient(device, timeout=timeout) as client:
                # Check if this is definitely a Utec device by looking for key services
                services = await client.get_services()

                has_data_service = bool(services.get_service(str(DeviceServiceUUID.DATA.value)))

                # Get more device details if this is a Utec device
                if has_data_service:
                    # Here you could read device characteristics to get model, firmware version, etc.
                    # This is device-specific so would need to be customized
                    device_info["confirmed_utec_device"] = True
                    # Example: device_info["model"] = await get_model_from_device(client)
                else:
                    device_info["confirmed_utec_device"] = False

                return device_info

        except Exception as e:
            logger.error(f"Error getting details for device {address}: {str(e)}")
            return None

# Standalone function for simpler usage
async def discover_utec_devices(timeout: float = 5.0) -> list[dict]:
    """Discover Utec BLE devices.

    Args:
        timeout: Scan timeout in seconds

    Returns:
        List of discovered device details
    """
    scanner = UtecDeviceScanner()
    return await scanner.discover(timeout)


async def connect_and_create_device(device_info: dict, password: Optional[str] = None) -> Optional[UtecBleDevice]:
    """Create a UtecBleDevice instance from discovered device information.

    Args:
        device_info: Device information from discovery
        password: Optional device password

    Returns:
        Configured UtecBleDevice instance or None if connection fails
    """
    try:
        address = device_info["address"]
        name = device_info["name"]

        # Create device instance
        device = UtecBleDevice(
            mac_address=address,
            name=name,
            password=password
        )

        # Test connection to verify device works
        await device.connect()
        await device.disconnect()

        logger.info(f"Successfully created and tested device: {name} ({address})")
        return device

    except Exception as e:
        logger.error(f"Failed to create device: {str(e)}")
        return None