"""Utecio Device Utils"""

from dataclasses import dataclass, field
import logging
import struct
import datetime
from typing import List, Optional, Union

logger = logging.getLogger(__name__)


def date_from_4bytes(byte_array: bytes) -> Optional[datetime.datetime]:
    """Convert a 4-byte array to a datetime object.

    Bit format:
    - Bits 0-5: Seconds (0-59)
    - Bits 6-11: Minutes (0-59)
    - Bits 12-16: Hours (0-23)
    - Bits 17-21: Day (1-31)
    - Bits 22-25: Month (1-12)
    - Bits 26-31: Year offset from 2000

    Args:
        byte_array: 4-byte data containing packed date/time

    Returns:
        Datetime object or None if conversion fails
    """
    if byte_array is None or len(byte_array) < 4:
        return None

    try:
        value = struct.unpack('>I', byte_array[:4])[0]

        seconds = value & 0x3F  # 6 bits (0-5)
        minutes = (value >> 6) & 0x3F  # 6 bits (6-11)
        hours = (value >> 12) & 0x1F  # 5 bits (12-16)
        day = (value >> 17) & 0x1F  # 5 bits (17-21)
        month = ((value >> 22) & 0x0F)  # 4 bits (22-25)
        year = ((value >> 26) & 0x3F) + 2000  # 6 bits (26-31)

        # Validate date components
        if not (1 <= month <= 12 and 1 <= day <= 31 and 0 <= hours <= 23 and
                0 <= minutes <= 59 and 0 <= seconds <= 59):
            return None

        return datetime.datetime(year, month, day, hours, minutes, seconds)
    except (ValueError, struct.error):
        return None


def bytes_to_int2(byte_array: bytes) -> int:
    """Convert a 2-byte array to an integer using little-endian format.

    Args:
        byte_array: 2-byte data

    Returns:
        Integer value
    """
    if byte_array is None or len(byte_array) < 2:
        return 0

    return int.from_bytes(byte_array[:2], byteorder='little')


def bytes_to_int4(byte_array: bytes, offset: int = 0) -> int:
    """Convert a 4-byte array to an integer using big-endian format.

    Args:
        byte_array: Byte array containing the data
        offset: Starting position in the array

    Returns:
        Integer value
    """
    if byte_array is None or offset < 0 or offset + 4 > len(byte_array):
        return 0

    return int.from_bytes(byte_array[offset:offset+4], byteorder='big')


def bytes_to_ascii(data: bytes) -> Optional[str]:
    """Convert bytes to a ASCII string, stopping at first null byte.

    Args:
        data: Byte array to convert

    Returns:
        Decoded string or None if decoding fails
    """
    if not data:
        return None

    # Find first null byte if present
    try:
        null_pos = data.index(0)
        data = data[:null_pos]
    except ValueError:
        # No null byte found, use the whole array
        pass

    try:
        return data.decode("ISO8859-1")
    except UnicodeDecodeError:
        return None


def int_to_bytes(value: int, size: int, byteorder: str = 'little') -> bytes:
    """Convert an integer to a byte array.

    Args:
        value: Integer to convert
        size: Number of bytes to use
        byteorder: Byte order ('little' or 'big')

    Returns:
        Byte array representing the integer
    """
    return value.to_bytes(size, byteorder=byteorder)


def decode_password(password: int) -> str:
    """Decode the password integer to the Admin Password string.

    The format appears to be:
    - First digit indicates password length
    - Remaining digits are the actual password, potentially padded with zeros

    Args:
        password: Password value as an integer

    Returns:
        Decoded password string
    """
    try:
        logger.info('password: %s', password)
        # Convert to 4-byte array in little-endian
        byte_array = int_to_bytes(password, 4, 'little')
        logger.info('byte_array: %s', byte_array)

        # Create hex representation of bytes in reverse order
        hex_str = ''.join(f'{b:02x}' for b in reversed(byte_array))
        logger.info('Hex String: %s', hex_str)

        # First digit indicates expected length
        expected_length = int(hex_str[0])

        # If first digit is 0, return original password as string
        if expected_length == 0:
            logger.info('Length is 0. Password is a string. Returning Password: %s', password)
            return str(password)

        # Convert remaining hex to decimal
        password_value = int(hex_str[1:], 16)
        logger.info('Password converted from hex to dec: %s', password_value)
        password_str = str(password_value)
        logger.info('Converted Password string: %s', password_str)

        # Pad with leading zeros if needed
        if len(password_str) < expected_length:
            password_str = password_str.zfill(expected_length)
            logger.info('password padded to meet expected length. Password: %s', password_str)

        return password_str
    except Exception as e:
        # Log the error instead of printing
        logger.error(f"Error decoding password: {e}")
        return str(password)  # Fallback to string representation

@dataclass
class DeviceDefinition:
    model: str = ""
    # Core features
    lock: bool = False
    door: bool = False
    keypad: bool = False

    # Authentication methods
    fingprinter: bool = False
    doublefp: bool = False
    bluetooth: bool = False
    rfid: bool = False
    rfid_once: bool = False
    rfid_twice: bool = False
    smartphone_nfc: bool = False

    # Automatic features
    autobolt: bool = False
    autolock: bool = False
    autounlock: bool = False
    passageautolock: bool = False

    # Updates and connectivity
    update_ota: bool = False
    update_oad: bool = False
    update_wifi: bool = False
    update_2642: bool = False
    bt264: bool = False
    keepalive: bool = False
    zwave: bool = False

    # Settings and modes
    alerts: bool = False
    mutemode: bool = False
    passage: bool = False
    lockout: bool = False
    manual: bool = False
    shakeopen: bool = False
    direction: bool = False
    isautodirection: bool = False

    # Administrative features
    moreadmin: bool = False
    morepwd: bool = False
    timelimit: bool = False
    morelanguage: bool = False
    needregristerpwd: bool = False
    locklocal: bool = False

    # System properties
    havesn: bool = False
    clone: bool = False
    customuserid: bool = False
    doorsensor: bool = False
    needreadmodel: bool = False
    needsycbuser: bool = False
    bt_close: bool = False
    singlelatchboltmortic: bool = False
    ishomekit: bool = False
    isyeeuu: bool = False

    # Arrays and counters
    secondsarray: List[int] = field(default_factory=list)
    mtimearray: List[int] = field(default_factory=list)
    adduserremovenum: int = 4

def create_device_capabilities(name: str, model: str, features: dict[str, bool]) -> type:
    """Factory function to create device classes with specific features."""
    return type(name, (DeviceDefinition,), {
        'model': model,
        '__init__': lambda self: self.__dict__.update(features)
    })