"""Base Device Class for Utecio Devices"""

import asyncio
import datetime
import logging

from collections.abc import Awaitable, Callable
from typing import Any, Optional

from bleak import BleakClient
from bleak.exc import BleakError
from bleak.backends.characteristic import BleakGATTCharacteristic
from bleak.backends.device import BLEDevice
from bleak_retry_connector import establish_connection, BleakNotFoundError, get_device

from ..util import decode_password, bytes_to_int2, DeviceDefinition
from src.crypto import UtecEncryption, UtecKeyExchange
from src.exceptions import (
    UtecBleError,
    UtecConnectionError,
    UtecProtocolError,
    UtecBleDeviceError,
    UtecBleNotFoundError
)
from src.const import (
    DEVICE_CONFIGS,
    LOCK_MODE,
    BOLT_STATUS,
    BATTERY_LEVEL,
    CRC8Table,
    BleResponseCode,
    BLECommandCode,
    DeviceServiceUUID
)

Logger = logging.getLogger(__name__)

class UtecBleDevice:
    def __init__(
        self,
        uid: str,
        password: str,
        mac_uuid: Any,
        device_name: str,
        wurx_uuid: Any = None,
        device_model: str = "",
        async_bledevice_callback: Callable[[str], Awaitable[BLEDevice | str]] = None,
        error_callback: Callable[[str, Exception], None] = None,
    ):
        self.mac_uuid = mac_uuid
        self.wurx_uuid = wurx_uuid
        self.uid = uid
        self.password: str = password
        self.name = device_name
        self.model: str = device_model
        self.capabilities: Optional[DeviceDefinition] = None
        self._requests: list[UtecBleRequest] = []
        self.config: dict[str, Any]
        self.async_bledevice_callback = async_bledevice_callback
        self.error_callback = error_callback
        self.mute: bool = False
        self.sn: str = ""
        self.calendar: datetime.datetime
        self.is_busy = False
        self.device_time_offset: datetime.timedelta

    @classmethod
    def from_json(cls, json_config: dict[str, Any]):
        new_device = cls(
            device_name=json_config["name"],
            uid=str(json_config["user"]["uid"]),
            password=decode_password(json_config["user"]["password"]),
            mac_uuid=json_config["uuid"],
            device_model=json_config["model"],
        )
        if json_config["params"]["extend_ble"]:
            new_device.wurx_uuid = json_config["params"]["extend_ble"]
        new_device.sn = json_config["params"]["serialnumber"]
        new_device.model = json_config["model"]
        new_device.config = json_config
        
        if new_device.model in DEVICE_CONFIGS:
            new_device.capabilities = DEVICE_CONFIGS[new_device.model]
        else:
            new_device.capabilities = DEVICE_CONFIGS["Utec-Generic"]
        
        return new_device

    async def async_update_status(self):
        pass

    def error(self, e: Exception, note: str = "") -> Exception:
        if note:
            e.add_note(e)

        if self.error_callback:
            self.error_callback(e)

        self.debug("(%s) %s", self.mac_uuid, e)
        return e

    def debug(self, msg: object, *args: object):
        if Logger.level < 20:
            Logger.debug(msg, args)

    def add_request(self, request: "UtecBleRequest", priority: bool = False):
        request.device = self
        if priority:
            self._requests.insert(0, request)
        else:
            self._requests.append(request)

    async def send_requests(self) -> bool:
        client: BleakClient = None
        try:
            if len(self._requests) < 1:
                raise self.error(
                    UtecBleError(
                        f"Unable to process requests for {self.name}({self.mac_uuid}).",
                        "No commands to send.",
                    )
                )

            self.is_busy = True
            try:
                if not (device := await self._get_bledevice(self.mac_uuid)):
                    raise BleakNotFoundError()
                client = await establish_connection(
                    client_class=BleakClient,
                    device=device,
                    name=self.mac_uuid,
                    max_attempts=1 if self.wurx_uuid else 2,
                    ble_device_callback=self._brc_get_lock_device,
                )
            except (BleakNotFoundError, BleakError):
                try:
                    if not self.wurx_uuid:
                        raise

                    await self.async_wakeup_device()
                    if not (device := await self._get_bledevice(self.mac_uuid)):
                        raise BleakNotFoundError("Wakeup device not found.")

                    client = await establish_connection(
                        client_class=BleakClient,
                        device=device,
                        name=self.mac_uuid,
                        max_attempts=2,
                        ble_device_callback=self._brc_get_lock_device,
                    )
                except (BleakError, BleakNotFoundError):
                    raise self.error(
                        UtecBleNotFoundError(
                            f"Could not connect to device {self.name}({self.mac_uuid}).",
                            "Device not found after 2 attempts.",
                        )
                    ) from None

            try:
                aes_key = await UtecKeyExchange.get_shared_key(
                    client=client, device=self
                )
            except Exception:
                raise self.error(
                    UtecBleDeviceError(
                        f"Error communicating with device {self.name}({self.mac_uuid}).",
                        "Could not retrieve shared key.",
                    )
                ) from None

            for request in self._requests[:]:
                if not request.sent or not request.response.completed:
                    Logger.debug("(%s) Sending command - %s (%s)",self.mac_uuid,request.command.name,request.package.hex())
                    request.aes_key = aes_key
                    request.device = self
                    request.sent = True
                    try:
                        await request._get_response(client)
                        self._requests.remove(request)

                    except Exception:
                        raise self.error(
                            UtecBleDeviceError(
                                f"Error communicating with device {self.name}({self.mac_uuid}).",
                                f"Command {request.command.name} failed.",
                            )
                        ) from None

        except Exception:  # unhandled
            raise

        finally:
            self._requests.clear()
            if client:
                await client.disconnect()
            self.is_busy = False

    async def _get_bledevice(self, address: str) -> BLEDevice:
        device = (
            await self.async_bledevice_callback(address)
            if self.async_bledevice_callback
            else await get_device(address)
        )
        return device

    async def _brc_get_lock_device(self) -> BLEDevice:
        return await self._get_bledevice(self.mac_uuid)

    async def _brc_get_wurx_device(self) -> BLEDevice:
        return await self._get_bledevice(self.wurx_uuid)

    async def async_wakeup_device(self):
        if not (device := await self._get_bledevice(self.wurx_uuid)):
            raise BleakNotFoundError()

        wclient: BleakClient = await establish_connection(
            client_class=BleakClient,
            device=device,
            name=self.wurx_uuid,
            max_attempts=2,
            ble_device_callback=self._brc_get_wurx_device,
        )
        self.debug("(%s) Wake-up reciever %s connected.", self.mac_uuid, self.wurx_uuid)
        await wclient.disconnect()

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
                Logger.warning(
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
            Logger.error(error_msg)
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
            Logger.warning(
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
            Logger.debug(
                "(%s) Response %s (%s): %s",
                self.device.mac_uuid,
                self.command.name if self.command else "Unknown",
                "Success" if self.success else "Failed",
                self.package.hex(),
            )

            if self.command:
                await self._dispatch_response_handler()

            Logger.debug(
                f"({self.device.mac_uuid}) Command Completed - {self.command.name if self.command else 'Unknown'}"
            )

        except Exception as e:
            error_msg = f"({self.device.mac_uuid}) Error processing response: {str(e)}"
            Logger.error(error_msg)

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
        Logger.debug(
            f"({self.device.mac_uuid}) lock:{self.device.lock_mode} "
            f"({LOCK_MODE.get(self.device.lock_mode, 'Unknown')}) | "
            f"bolt:{self.device.bolt_status} "
            f"({BOLT_STATUS.get(self.device.bolt_status, 'Unknown')})"
        )

    async def _handle_set_lock_status(self) -> None:
        """Handle set lock status response."""
        self.device.lock_mode = self.data[0]
        Logger.debug(
            f"({self.device.mac_uuid}) workmode:{self.device.lock_mode}"
        )

    async def _handle_battery(self) -> None:
        """Handle battery status response."""
        self.device.battery = int(self.data[0])
        Logger.debug(
            f"({self.device.mac_uuid}) power level:{self.device.battery}, "
            f"{BATTERY_LEVEL.get(self.device.battery, 'Unknown')}"
        )

    async def _handle_autolock(self) -> None:
        """Handle autolock time response."""
        self.device.autolock_time = bytes_to_int2(self.data[:2])
        Logger.debug(
            f"({self.device.mac_uuid}) autolock:{self.device.autolock_time}"
        )

    async def _handle_set_autolock(self) -> None:
        """Handle set autolock time response."""
        if self.success:
            self.device.autolock_time = bytes_to_int2(self.data[:2])
            Logger.debug(
                f"({self.device.mac_uuid}) autolock:{self.device.autolock_time}"
            )

    async def _handle_serial_number(self) -> None:
        """Handle serial number response."""
        self.device.sn = self.data.decode("ISO8859-1")
        Logger.debug(
            f"({self.device.mac_uuid}) serial:{self.device.sn}"
        )

    async def _handle_mute(self) -> None:
        """Handle mute status response."""
        self.device.mute = bool(self.data[0])
        Logger.debug(
            f"({self.device.mac_uuid}) mute:{self.device.mute}"
        )

    async def _handle_set_work_mode(self) -> None:
        """Handle set work mode response."""
        if self.success:
            self.device.lock_mode = self.data[0]
            Logger.debug(
                f"({self.device.mac_uuid}) workmode:{self.device.lock_mode}"
            )

    async def _handle_unlock(self) -> None:
        """Handle unlock response."""
        Logger.debug(
            f"({self.device.mac_uuid}) {self.device.name} - Unlocked."
        )

    async def _handle_bolt_lock(self) -> None:
        """Handle bolt lock response."""
        Logger.debug(
            f"({self.device.mac_uuid}) {self.device.name} - Bolt Locked"
        )

    async def _handle_lock_status_extended(self) -> None:
        """Handle extended lock status response."""
        self.device.lock_status = int(self.data[0])
        self.device.bolt_status = int(self.data[1])
        Logger.debug(
            f"({self.device.mac_uuid}) lock:{self.device.lock_status} | "
            f"bolt:{self.device.bolt_status}"
        )

        # Extended information if available
        if self.length > 16:
            self.device.battery = int(self.data[2])
            self.device.lock_mode = int(self.data[3])
            self.device.mute = bool(self.data[4])
            Logger.debug(
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