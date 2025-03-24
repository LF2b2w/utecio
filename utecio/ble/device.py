import datetime
from logging import logger

from collections.abc import Awaitable, Callable
from typing import Any, Optional

from bleak.backends.device import BLEDevice
from bleak import BleakClient
from bleak.exc import BleakError
from bleak_retry_connector import establish_connection, BleakNotFoundError, get_device

from utecio.const import DEVICE_CONFIGS


from ..util import decode_password, DeviceDefinition
from ..api import UtecBleDeviceKey, UtecBleRequest
from ..exceptions import UtecBleDeviceError, UtecBleError, UtecBleNotFoundError


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
        if logger.level < 20:
            logger.debug(msg, args)

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
                aes_key = await UtecBleDeviceKey.get_shared_key(
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
                    # logger.debug("(%s) Sending command - %s (%s)",self.mac_uuid,request.command.name,request.package.hex())
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
