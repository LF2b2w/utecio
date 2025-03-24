"""Utec Cloud API client for accessing Utec smart devices remotely."""
from __future__ import annotations

import asyncio
import json
import logging
import secrets
import string
import time
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Union, cast
from urllib.parse import urljoin

from aiohttp import ClientError, ClientResponse, ClientSession, ClientTimeout

from .ble.lock import UtecBleLock
from .exceptions import (
    UtecApiError,
    UtecAuthError,
    UtecConnectionError,
    UtecTimeoutError,
)

# Configure module logger
logger = logging.getLogger(__name__)

# API Constants
API_TIMEOUT = 30  # seconds
BASE_URL_UEMC = "https://uemc.u-tec.com/"
BASE_URL_CLOUD = "https://cloud.u-tec.com/"

# API Headers
HEADERS = {
    "accept": "*/*",
    "content-type": "application/x-www-form-urlencoded",
    "accept-encoding": "gzip, deflate, br",
    "user-agent": "U-tec/2.1.14 (iPhone; iOS 15.1; Scale/3.00)",
    "accept-language": "en-US;q=1, it-US;q=0.9",
}

# API Authentication Parameters
APP_ID = "13ca0de1e6054747c44665ae13e36c2c"
CLIENT_ID = "1375ac0809878483ee236497d57f371f"
VERSION = "V3.2"


@dataclass
class UtecAddress:
    """Represents a physical address in the Utec system."""

    id: str
    name: str
    address: str
    created_at: str
    raw_data: Dict[str, Any]

    @classmethod
    def from_api(cls, data: Dict[str, Any]) -> UtecAddress:
        """Create an address object from API response data."""
        return cls(
            id=data["id"],
            name=data.get("name", ""),
            address=data.get("address", ""),
            created_at=data.get("created_at", ""),
            raw_data=data,
        )


@dataclass
class UtecRoom:
    """Represents a room in the Utec system."""

    id: str
    name: str
    address_id: str
    created_at: str
    raw_data: Dict[str, Any]

    @classmethod
    def from_api(cls, data: Dict[str, Any]) -> UtecRoom:
        """Create a room object from API response data."""
        return cls(
            id=data["id"],
            name=data.get("name", ""),
            address_id=data.get("address_id", ""),
            created_at=data.get("created_at", ""),
            raw_data=data,
        )


class UtecApiClient:
    """Low-level API client for making requests to the Utec cloud service."""

    def __init__(
        self,
        session: Optional[ClientSession] = None,
        timeout: int = API_TIMEOUT,
    ) -> None:
        """Initialize the API client.

        Args:
            session: Optional existing aiohttp session
            timeout: Request timeout in seconds
        """
        self._session = session
        self._timeout = ClientTimeout(total=timeout)
        self._last_response: Optional[Dict[str, Any]] = None

    async def _ensure_session(self) -> ClientSession:
        """Ensure a client session exists and return it."""
        if self._session is None or self._session.closed:
            self._session = ClientSession(timeout=self._timeout)
        return self._session

    async def close(self) -> None:
        """Close the client session if it exists."""
        if self._session and not self._session.closed:
            await self._session.close()
            self._session = None

    async def post(
        self,
        url: str,
        headers: Dict[str, str],
        data: Dict[str, str],
        expected_status: int = 200,
    ) -> Dict[str, Any]:
        """Make a POST request to the API.

        Args:
            url: API endpoint URL
            headers: Request headers
            data: POST form data
            expected_status: Expected HTTP status code

        Returns:
            Parsed JSON response

        Raises:
            UtecConnectionError: If connection fails
            UtecTimeoutError: If request times out
            UtecApiError: If API returns an error or unexpected status code
        """
        session = await self._ensure_session()

        try:
            async with session.post(
                url, headers=headers, data=data, timeout=self._timeout
            ) as response:
                return await self._handle_response(response, expected_status)
        except asyncio.TimeoutError as err:
            raise UtecTimeoutError(f"Request to {url} timed out") from err
        except ClientError as err:
            raise UtecConnectionError(f"Failed to connect to {url}: {err}") from err

    async def _handle_response(
        self, response: ClientResponse, expected_status: int = 200
    ) -> Dict[str, Any]:
        """Process API response and handle errors.

        Args:
            response: aiohttp response object
            expected_status: Expected HTTP status code

        Returns:
            Parsed JSON response

        Raises:
            UtecApiError: If API returns an error or unexpected status code
        """
        if response.status != expected_status:
            error_text = await response.text()
            raise UtecApiError(
                f"Unexpected status code: {response.status}, response: {error_text}"
            )

        try:
            json_response = await response.json()
            self._last_response = json_response

            # Check for API error responses
            if json_response.get("error"):
                error_msg = json_response.get("error_message", "Unknown API error")
                error_code = json_response.get("error_code", "unknown")
                raise UtecApiError(f"API error {error_code}: {error_msg}")

            return json_response
        except json.JSONDecodeError as err:
            text_response = await response.text()
            raise UtecApiError(f"Invalid JSON response: {text_response}") from err


class UtecCloud:
    """Client for the Utec cloud service API.

    This client handles authentication and data retrieval from the Utec cloud services,
    allowing access to addresses, rooms, and devices associated with an account.
    """

    def __init__(
        self, email: str, password: str, session: Optional[ClientSession] = None
    ) -> None:
        """Initialize U-Tec cloud client.

        Args:
            email: Account email
            password: Account password
            session: Optional existing aiohttp session
        """
        self.email: str = email
        self.password: str = password
        self.token: Optional[str] = None
        self.token_expiry: float = 0
        self.mobile_uuid: str = self._generate_mobile_uuid(32)
        self.timezone: str = "-4"  # Default timezone offset

        # Internal state
        self.addresses: List[UtecAddress] = []
        self.rooms: List[UtecRoom] = []
        self.devices: List[Dict[str, Any]] = []

        # API client
        self.api = UtecApiClient(session)
        self._connected: bool = False

    @property
    def is_connected(self) -> bool:
        """Return whether the client is connected and authenticated."""
        return self._connected and self.token is not None

    def _generate_mobile_uuid(self, length: int = 32) -> str:
        """Generate a random mobile device UUID.

        Args:
            length: Length of the UUID string

        Returns:
            Random UUID string
        """
        chars = string.ascii_uppercase + string.digits
        return "".join(secrets.choice(chars) for _ in range(length))

    async def _fetch_token(self) -> None:
        """Fetch authentication token from the API.

        Raises:
            UtecApiError: If token retrieval fails
        """
        url = urljoin(BASE_URL_UEMC, "app/token")
        data = {
            "appid": APP_ID,
            "clientid": CLIENT_ID,
            "timezone": self.timezone,
            "uuid": self.mobile_uuid,
            "version": VERSION,
        }

        logger.debug("Fetching authentication token")
        response = await self.api.post(url, HEADERS, data)

        if not response.get("data", {}).get("token"):
            raise UtecApiError("Token not found in response")

        self.token = response["data"]["token"]
        # Set token expiry (tokens typically last 24 hours)
        self.token_expiry = time.time() + 24 * 60 * 60
        logger.debug("Authentication token retrieved successfully")

    async def _login(self) -> None:
        """Log in to the Utec account using email and password.

        Raises:
            UtecAuthError: If login fails due to invalid credentials
            UtecApiError: If login fails for other reasons
        """
        if not self.token:
            await self._fetch_token()

        url = urljoin(BASE_URL_CLOUD, "app/user/login")
        auth_data = {
            "email": self.email,
            "password": self.password,
            "timestamp": str(time.time()),
        }
        data = {
            "data": json.dumps(auth_data),
            "token": self.token,
        }

        logger.debug("Authenticating with account credentials")
        try:
            response = await self.api.post(url, HEADERS, data)

            if response.get("error"):
                error_msg = response.get("error_message", "Login failed")
                raise UtecAuthError(f"Authentication failed: {error_msg}")

            self._connected = True
            logger.info("Successfully authenticated with Utec cloud service")
        except UtecApiError as err:
            self._connected = False
            if "not found" in str(err).lower():
                raise UtecAuthError("Invalid email or password") from err
            raise

    async def _ensure_authenticated(self) -> None:
        """Ensure the client is authenticated, refreshing token if needed."""
        if not self.is_connected or time.time() >= self.token_expiry:
            await self.connect()

    async def connect(self) -> None:
        """Connect to the Utec cloud service and authenticate.

        Raises:
            UtecAuthError: If authentication fails
            UtecApiError: If API access fails
            UtecConnectionError: If connection fails
        """
        try:
            await self._fetch_token()
            await self._login()
        except Exception as err:
            self._connected = False
            raise

    async def _get_addresses(self) -> List[UtecAddress]:
        """Fetch all addresses associated with the account.

        Returns:
            List of address objects

        Raises:
            UtecApiError: If API access fails
        """
        await self._ensure_authenticated()

        url = urljoin(BASE_URL_CLOUD, "app/address")
        body_data = {"timestamp": str(time.time())}
        data = {"data": json.dumps(body_data), "token": self.token}

        logger.debug("Fetching addresses")
        response = await self.api.post(url, HEADERS, data)

        addresses = []
        for address_data in response.get("data", []):
            addresses.append(UtecAddress.from_api(address_data))

        self.addresses = addresses
        logger.debug(f"Retrieved {len(addresses)} addresses")
        return addresses

    async def _get_rooms_for_address(self, address: UtecAddress) -> List[UtecRoom]:
        """Get all rooms within an address.

        Args:
            address: Address object to get rooms for

        Returns:
            List of room objects

        Raises:
            UtecApiError: If API access fails
        """
        await self._ensure_authenticated()

        url = urljoin(BASE_URL_CLOUD, "app/room")
        body_data = {"id": address.id, "timestamp": str(time.time())}
        data = {"data": json.dumps(body_data), "token": self.token}

        logger.debug(f"Fetching rooms for address: {address.name} ({address.id})")
        response = await self.api.post(url, HEADERS, data)

        rooms = []
        for room_data in response.get("data", []):
            rooms.append(UtecRoom.from_api(room_data))

        logger.debug(f"Retrieved {len(rooms)} rooms for address {address.id}")
        return rooms

    async def _get_devices_in_room(self, room: UtecRoom) -> List[Dict[str, Any]]:
        """Fetch all devices located in a room.

        Args:
            room: Room object to get devices for

        Returns:
            List of device data dictionaries

        Raises:
            UtecApiError: If API access fails
        """
        await self._ensure_authenticated()

        url = urljoin(BASE_URL_CLOUD, "app/device/list")
        body_data = {"room_id": room.id, "timestamp": str(time.time())}
        data = {"data": json.dumps(body_data), "token": self.token}

        logger.debug(f"Fetching devices for room: {room.name} ({room.id})")
        response = await self.api.post(url, HEADERS, data)

        devices = response.get("data", [])
        logger.debug(f"Retrieved {len(devices)} devices for room {room.id}")
        return devices

    async def close(self) -> None:
        """Close the API client session."""
        await self.api.close()

    async def sync_devices(self) -> None:
        """Synchronize all addresses, rooms, and devices from the cloud.

        This method retrieves all data associated with the account,
        populating the addresses, rooms, and devices lists.

        Raises:
            UtecAuthError: If authentication fails
            UtecApiError: If API access fails
            UtecConnectionError: If connection fails
        """
        logger.info("Starting device synchronization with Utec cloud")

        # Make sure we're connected and authenticated
        await self._ensure_authenticated()

        # Clear existing data
        self.addresses = []
        self.rooms = []
        self.devices = []

        # Get addresses
        addresses = await self._get_addresses()

        # Get rooms for each address
        all_rooms = []
        for address in addresses:
            rooms = await self._get_rooms_for_address(address)
            all_rooms.extend(rooms)

        self.rooms = all_rooms

        # Get devices for each room
        all_devices = []
        for room in all_rooms:
            devices = await self._get_devices_in_room(room)
            all_devices.extend(devices)

        self.devices = all_devices
        logger.info(f"Sync complete: {len(addresses)} addresses, {len(all_rooms)} rooms, {len(all_devices)} devices")

    async def get_ble_devices(self, sync: bool = True) -> List[UtecBleLock]:
        """Get all BLE-capable devices associated with the account.

        Args:
            sync: Whether to synchronize data from the cloud first

        Returns:
            List of UtecBleLock instances

        Raises:
            UtecAuthError: If authentication fails
            UtecApiError: If API access fails
            UtecConnectionError: If connection fails
        """
        if sync:
            await self.sync_devices()

        ble_devices = []
        for device_data in self.devices:
            try:
                device = UtecBleLock.from_json(device_data)
                if device.capabilities.bluetooth:
                    ble_devices.append(device)
            except Exception as e:
                logger.warning(f"Failed to process device: {e}")

        logger.info(f"Found {len(ble_devices)} BLE-capable devices")
        return ble_devices

    async def get_device_details(self, device_id: str) -> Optional[Dict[str, Any]]:
        """Get detailed information about a specific device.

        Args:
            device_id: ID of the device to get details for

        Returns:
            Device details dictionary or None if not found

        Raises:
            UtecAuthError: If authentication fails
            UtecApiError: If API access fails
        """
        await self._ensure_authenticated()

        url = urljoin(BASE_URL_CLOUD, "app/device/detail")
        body_data = {"id": device_id, "timestamp": str(time.time())}
        data = {"data": json.dumps(body_data), "token": self.token}

        logger.debug(f"Fetching details for device {device_id}")

        try:
            response = await self.api.post(url, HEADERS, data)
            device_data = response.get("data")

            if not device_data:
                logger.warning(f"No data returned for device {device_id}")
                return None

            return device_data
        except UtecApiError as e:
            logger.error(f"Error fetching device details: {e}")
            return None

    async def get_device_history(
        self, device_id: str, page: int = 1, limit: int = 20
    ) -> List[Dict[str, Any]]:
        """Get activity history for a device.

        Args:
            device_id: ID of the device
            page: Page number for pagination
            limit: Number of records per page

        Returns:
            List of history event records

        Raises:
            UtecAuthError: If authentication fails
            UtecApiError: If API access fails
        """
        await self._ensure_authenticated()

        url = urljoin(BASE_URL_CLOUD, "app/device/history")
        body_data = {
            "id": device_id,
            "page": page,
            "limit": limit,
            "timestamp": str(time.time())
        }
        data = {"data": json.dumps(body_data), "token": self.token}

        logger.debug(f"Fetching history for device {device_id}")

        try:
            response = await self.api.post(url, HEADERS, data)
            history_data = response.get("data", [])

            logger.debug(f"Retrieved {len(history_data)} history records")
            return history_data
        except UtecApiError as e:
            logger.error(f"Error fetching device history: {e}")
            return []