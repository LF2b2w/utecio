"""Ble API for Utecio"""

import asyncio
import logging
from typing import Optional

from bleak import BleakClient, BleakScanner, AdvertisementData
from bleak.backends.characteristic import BleakGATTCharacteristic
from bleak.backends.device import BLEDevice

from utecio.ble.device import UtecBleDevice
from utecio.crypto import UtecEncryption, UtecKeyExchange
from utecio.util import bytes_to_int2
from utecio.exceptions import (
    UtecBleError,
    UtecConnectionError,
    UtecProtocolError
)
from utecio.const import (
    LOCK_MODE,
    BOLT_STATUS,
    BATTERY_LEVEL,
    UTEC_DEVICE_PREFIXES,
    UTEC_MANUFACTURER_IDS,
    CRC8Table,
    BleResponseCode,
    BLECommandCode,
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

        # Start scanner with callback
        self._scanner.register_detection_callback(_device_found_callback)
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

class UtecBleRequest:
    """Handles creating and sending BLE commands to Utec devices."""

    def __init__(
        self,
        command: BLECommandCode,
        device: UtecBleDevice = None,
        data: bytes = bytes(),
        auth_required: bool = False,
    ):
        """Initialize a BLE request.

        Args:
            command: The BLE command to send
            device: The target Utec device
            data: Optional data payload for the command
            auth_required: Whether authentication is required for this command
        """
        self.command = command
        self.device = device
        self.uuid = DeviceServiceUUID.DATA.value
        self.response: Optional[UtecBleResponse] = None
        self.aes_key: bytes = bytes()
        self.sent = False
        self.data = data
        self.auth_required = auth_required
        self.request_timeout = 10.0  # Default timeout in seconds

        # Initialize the request buffer
        self.buffer = bytearray(5120)
        self.buffer[0] = 0x7F  # Header byte
        length_bytes = bytearray(int.to_bytes(2, 2, "little"))
        self.buffer[1] = length_bytes[0]
        self.buffer[2] = length_bytes[1]
        self.buffer[3] = command.value
        self._write_pos = 4

        # Build the request package
        self._build_package()

    def _build_package(self) -> None:
        """Build the complete request package with all components."""
        if self.auth_required and self.device:
            self._append_auth(self.device.uid, self.device.password)
        if self.data:
            self._append_data(self.data)
        self._append_length()
        self._append_crc()

    def _append_data(self, data: bytes) -> None:
        """Append data to the request buffer.

        Args:
            data: The data to append
        """
        data_len = len(data)
        self.buffer[self._write_pos : self._write_pos + data_len] = data
        self._write_pos += data_len

    def _append_auth(self, uid: str, password: str = "") -> None:
        """Append authentication data to the request buffer.

        Args:
            uid: The device UID
            password: The device password
        """
        if uid:
            uid_bytes = bytearray(int(uid).to_bytes(4, "little"))
            self.buffer[self._write_pos : self._write_pos + 4] = uid_bytes
            self._write_pos += 4

        if password:
            pwd_bytes = bytearray(int(password).to_bytes(4, "little"))
            # Encode password length in the high bits of the last byte
            pwd_bytes[3] = (len(password) << 4) | pwd_bytes[3]
            self.buffer[self._write_pos : self._write_pos + 4] = pwd_bytes[:4]
            self._write_pos += 4

    def _append_length(self) -> None:
        """Update the length field in the request header."""
        length_bytes = bytearray(int(self._write_pos - 2).to_bytes(2, "little"))
        self.buffer[1] = length_bytes[0]
        self.buffer[2] = length_bytes[1]

    def _append_crc(self) -> None:
        """Calculate and append the CRC checksum."""
        crc = UtecEncryption.calculate_crc8(self.buffer, CRC8Table, 3, self._write_pos)
        self.buffer[self._write_pos] = crc
        self._write_pos += 1

    @property
    def package(self) -> bytearray:
        """Get the complete request package.

        Returns:
            The prepared request package
        """
        return self.buffer[: self._write_pos]

    def encrypted_package(self, aes_key: bytes) -> bytearray:
        """Get the encrypted version of the request package.

        Args:
            aes_key: The AES key to use for encryption

        Returns:
            The encrypted package
        """
        return UtecEncryption.encrypt_package(self.package, aes_key)

    async def _get_response(self, client: BleakClient) -> None:
        """Send the request and wait for a response.

        Args:
            client: The BleakClient connection to use

        Raises:
            UtecConnectionError: If the request times out or communication fails
            UtecBleError: For other errors
        """
        self.response = UtecBleResponse(self, self.device)

        try:
            # Register for notifications and send the request
            await client.start_notify(self.uuid, self.response._receive_write_response)
            await client.write_gatt_char(
                self.uuid, self.encrypted_package(self.aes_key)
            )

            # Wait for response with timeout
            await asyncio.wait_for(
                self.response.response_completed.wait(),
                timeout=self.request_timeout
            )

        except asyncio.TimeoutError:
            raise UtecConnectionError(
                f"({self.device.mac_uuid}) Response timeout for command {self.command.name}"
            )
        except Exception as e:
            if isinstance(e, UtecBleError):
                raise
            raise UtecConnectionError(f"Failed to send command: {str(e)}") from e
        finally:
            # Always stop notifications
            try:
                await client.stop_notify(self.uuid)
            except Exception:
                logger.warning(
                    f"({self.device.mac_uuid}) Failed to stop notifications"
                )


class UtecBleResponse:
    """Processes and handles BLE responses from Utec devices."""

    def __init__(self, request: UtecBleRequest, device: UtecBleDevice):
        """Initialize a BLE response.

        Args:
            request: The original request
            device: The Utec device
        """
        self.buffer = bytearray()
        self.request = request
        self.response_completed = asyncio.Event()
        self.device = device

    async def _receive_write_response(
        self, sender: BleakGATTCharacteristic, data: bytearray
    ) -> None:
        """Handle incoming data from BLE notifications.

        Args:
            sender: The characteristic that sent the notification
            data: The notification data

        Raises:
            UtecBleError: If there's an error processing the response
        """
        try:
            # Decrypt and append the data
            decrypted_data = UtecEncryption.decrypt_package(data, self.request.aes_key)
            self._append(decrypted_data)

            # Check if we have a complete and valid response
            if self.completed and self.is_valid:
                await self._process_response()
                self.response_completed.set()
        except Exception as e:
            error_msg = f"({self.device.mac_uuid}) Error receiving write response: {str(e)}"
            logger.error(error_msg)
            raise UtecProtocolError(error_msg) from e

    def reset(self) -> None:
        """Reset the response buffer."""
        self.buffer = bytearray(0)

    def _append(self, data: bytearray) -> None:
        """Append decrypted data to the response buffer.

        Args:
            data: The decrypted data to append
        """
        if (self.length > 0 and self.buffer[0] == 0x7F) or data[0] == 0x7F:
            self.buffer += data

    def _parameter(self, index: int) -> Optional[bytearray]:
        """Extract a parameter from the response at the specified index.

        Args:
            index: The parameter index

        Returns:
            The parameter data or None if invalid
        """
        data_len = self.data_len
        if data_len < 3:
            return None

        param_size = (data_len - 2) - index
        if param_size <= 0:
            return None

        param_data = bytearray(param_size)
        param_data[:] = self.buffer[index + 4 : index + 4 + param_size]
        return param_data

    @property
    def is_valid(self) -> bool:
        """Check if the response is valid.

        Returns:
            True if the response is complete and valid
        """
        cmd = self.command
        return bool(self.completed and cmd and isinstance(cmd, BleResponseCode))

    @property
    def completed(self) -> bool:
        """Check if the response is complete.

        Returns:
            True if the response is complete
        """
        return bool(self.length > 3 and self.length >= self.package_len)

    @property
    def length(self) -> int:
        """Get the current length of the response buffer.

        Returns:
            The buffer length
        """
        return len(self.buffer)

    @property
    def data_len(self) -> int:
        """Get the data length from the response header.

        Returns:
            The data length
        """
        return (
            int.from_bytes(self.buffer[1:3], byteorder="little")
            if self.length > 3
            else 0
        )

    @property
    def package_len(self) -> int:
        """Get the total package length.

        Returns:
            The total package length
        """
        return self.data_len + 4 if self.length > 3 else 0

    @property
    def package(self) -> bytearray:
        """Get the complete response package.

        Returns:
            The response package
        """
        return self.buffer[: self.package_len - 1]

    @property
    def command(self) -> Optional[BleResponseCode]:
        """Get the response command.

        Returns:
            The response command or None if not complete
        """
        try:
            return BleResponseCode(self.buffer[3]) if self.completed else None
        except ValueError:
            logger.warning(
                f"({self.device.mac_uuid}) Unknown response code: {self.buffer[3]}"
            )
            return None

    @property
    def success(self) -> bool:
        """Check if the response indicates success.

        Returns:
            True if the response indicates success
        """
        return bool(self.completed and self.buffer[4] == 0)

    @property
    def data(self) -> bytearray:
        """Get the response data.

        Returns:
            The response data
        """
        if self.is_valid:
            return self.buffer[5 : self.data_len + 5]
        else:
            return bytearray()

    async def _process_response(self) -> None:
        """Process the complete response and dispatch to appropriate handler."""
        try:
            logger.debug(
                "(%s) Response %s (%s): %s",
                self.device.mac_uuid,
                self.command.name if self.command else "Unknown",
                "Success" if self.success else "Failed",
                self.package.hex(),
            )

            if self.command:
                await self._dispatch_response_handler()

            logger.debug(
                f"({self.device.mac_uuid}) Command Completed - {self.command.name if self.command else 'Unknown'}"
            )

        except Exception as e:
            error_msg = f"({self.device.mac_uuid}) Error processing response: {str(e)}"
            logger.error(error_msg)

    async def _dispatch_response_handler(self) -> None:
        """Route response to appropriate handler based on command type."""
        handlers = {
            BleResponseCode.GET_LOCK_STATUS: self._handle_lock_status,
            BleResponseCode.SET_LOCK_STATUS: self._handle_set_lock_status,
            BleResponseCode.GET_BATTERY: self._handle_battery,
            BleResponseCode.GET_AUTOLOCK: self._handle_autolock,
            BleResponseCode.SET_AUTOLOCK: self._handle_set_autolock,
            BleResponseCode.GET_SN: self._handle_serial_number,
            BleResponseCode.GET_MUTE: self._handle_mute,
            BleResponseCode.SET_WORK_MODE: self._handle_set_work_mode,
            BleResponseCode.UNLOCK: self._handle_unlock,
            BleResponseCode.BOLT_LOCK: self._handle_bolt_lock,
            BleResponseCode.LOCK_STATUS: self._handle_lock_status_extended,
        }

        handler = handlers.get(self.command)
        if handler:
            await handler()

    async def _handle_lock_status(self) -> None:
        """Handle lock status response."""
        self.device.lock_mode = int(self.data[0])
        self.device.bolt_status = int(self.data[1])
        logger.debug(
            f"({self.device.mac_uuid}) lock:{self.device.lock_mode} "
            f"({LOCK_MODE.get(self.device.lock_mode, 'Unknown')}) | "
            f"bolt:{self.device.bolt_status} "
            f"({BOLT_STATUS.get(self.device.bolt_status, 'Unknown')})"
        )

    async def _handle_set_lock_status(self) -> None:
        """Handle set lock status response."""
        self.device.lock_mode = self.data[0]
        logger.debug(
            f"({self.device.mac_uuid}) workmode:{self.device.lock_mode}"
        )

    async def _handle_battery(self) -> None:
        """Handle battery status response."""
        self.device.battery = int(self.data[0])
        logger.debug(
            f"({self.device.mac_uuid}) power level:{self.device.battery}, "
            f"{BATTERY_LEVEL.get(self.device.battery, 'Unknown')}"
        )

    async def _handle_autolock(self) -> None:
        """Handle autolock time response."""
        self.device.autolock_time = bytes_to_int2(self.data[:2])
        logger.debug(
            f"({self.device.mac_uuid}) autolock:{self.device.autolock_time}"
        )

    async def _handle_set_autolock(self) -> None:
        """Handle set autolock time response."""
        if self.success:
            self.device.autolock_time = bytes_to_int2(self.data[:2])
            logger.debug(
                f"({self.device.mac_uuid}) autolock:{self.device.autolock_time}"
            )

    async def _handle_serial_number(self) -> None:
        """Handle serial number response."""
        self.device.sn = self.data.decode("ISO8859-1")
        logger.debug(
            f"({self.device.mac_uuid}) serial:{self.device.sn}"
        )

    async def _handle_mute(self) -> None:
        """Handle mute status response."""
        self.device.mute = bool(self.data[0])
        logger.debug(
            f"({self.device.mac_uuid}) mute:{self.device.mute}"
        )

    async def _handle_set_work_mode(self) -> None:
        """Handle set work mode response."""
        if self.success:
            self.device.lock_mode = self.data[0]
            logger.debug(
                f"({self.device.mac_uuid}) workmode:{self.device.lock_mode}"
            )

    async def _handle_unlock(self) -> None:
        """Handle unlock response."""
        logger.debug(
            f"({self.device.mac_uuid}) {self.device.name} - Unlocked."
        )

    async def _handle_bolt_lock(self) -> None:
        """Handle bolt lock response."""
        logger.debug(
            f"({self.device.mac_uuid}) {self.device.name} - Bolt Locked"
        )

    async def _handle_lock_status_extended(self) -> None:
        """Handle extended lock status response."""
        self.device.lock_status = int(self.data[0])
        self.device.bolt_status = int(self.data[1])
        logger.debug(
            f"({self.device.mac_uuid}) lock:{self.device.lock_status} | "
            f"bolt:{self.device.bolt_status}"
        )

        # Extended information if available
        if self.length > 16:
            self.device.battery = int(self.data[2])
            self.device.lock_mode = int(self.data[3])
            self.device.mute = bool(self.data[4])
            logger.debug(
                f"({self.device.mac_uuid}) power level:{self.device.battery} | "
                f"mute:{self.device.mute} | mode:{self.device.lock_mode}"
            )


async def get_device_key(client: BleakClient, device: UtecBleDevice) -> bytes:
    """Get the encryption key for a device.

    Args:
        client: The BleakClient connection
        device: The Utec device

    Returns:
        The encryption key for the device

    Raises:
        UtecEncryptionError: If key exchange fails
    """
    return await UtecKeyExchange.get_shared_key(client, device)

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