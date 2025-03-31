"""Encryption handler for Utecio."""

import asyncio
import hashlib
import logging
import struct
from typing import List, Optional

from Crypto.Cipher import AES

from bleak import BleakClient
from ecdsa import SECP128r1, SigningKey
from ecdsa.ellipticcurve import Point

from src.exceptions import UtecEncryptionError
from src.const import DeviceKeyUUID

# Configure module logger
logger = logging.getLogger(__name__)

class UtecEncryption:
    """Handles encryption and decryption for Utec BLE communication."""

    @staticmethod
    def encrypt_package(package: bytearray, key: bytes) -> bytearray:
        """Encrypt a BLE package using AES-CBC mode."""
        try:
            package_len = len(package)
            num_chunks = (package_len // 16) + (1 if package_len % 16 > 0 else 0)
            encrypted = bytearray(num_chunks * 16)

            for chunk_idx in range(num_chunks):
                start = chunk_idx * 16
                chunk = package[start:start + min(16, package_len - start)]

                # Pad chunk to 16 bytes
                padded_chunk = bytearray(16)
                padded_chunk[:len(chunk)] = chunk

                # Encrypt chunk
                iv = bytearray(16)  # Zero IV
                cipher = AES.new(key, AES.MODE_CBC, iv)
                encrypted_chunk = cipher.encrypt(padded_chunk)

                encrypted[start:start + 16] = encrypted_chunk

            return encrypted
        except Exception as e:
            raise UtecEncryptionError(f"Encryption failed: {str(e)}") from e

    @staticmethod
    def decrypt_package(encrypted: bytearray, key: bytes) -> bytearray:
        """Decrypt a BLE package using AES-CBC mode."""
        try:
            iv = bytearray(16)  # Zero IV
            cipher = AES.new(key, AES.MODE_CBC, iv)
            return cipher.decrypt(encrypted)
        except Exception as e:
            raise UtecEncryptionError(f"Decryption failed: {str(e)}") from e

    @staticmethod
    def calculate_crc8(data: bytearray, crc8_table: List[int], start_index: int = 0, end_index: Optional[int] = None) -> int:
        """Calculate CRC8 checksum for data."""
        crc = 0
        end = len(data) if end_index is None else end_index

        for i in range(start_index, end):
            index = (crc ^ data[i]) & 0xFF
            crc = crc8_table[index]

        return crc


class UtecKeyExchange:
    """Manages encryption key exchange with Utec devices."""

    @staticmethod
    async def get_shared_key(client: BleakClient, device) -> bytes:
        """Determine and retrieve the appropriate shared encryption key."""

        try:
            # Prefer more secure methods first
            if client.services.get_characteristic(DeviceKeyUUID.ECC.value):
                logger.info(f"({client.address}) Using ECC encryption")
                return await UtecKeyExchange.get_ecc_key(client, device)

            if client.services.get_characteristic(DeviceKeyUUID.MD5.value):
                logger.info(f"({client.address}) Using MD5 encryption")
                return await UtecKeyExchange.get_md5_key(client, device)

            if client.services.get_characteristic(DeviceKeyUUID.STATIC.value):
                logger.warning(f"({client.address}) Using static key (less secure)")
                # Use config instead of hardcoded value
                static_prefix = getattr(device, 'encryption_prefix', b'Anviz.ut')
                return static_prefix + await client.read_gatt_char(DeviceKeyUUID.STATIC.value)

            raise NotImplementedError(f"({client.address}) Unknown encryption method")
        except Exception as e:
            if isinstance(e, NotImplementedError):
                raise
            raise UtecEncryptionError(f"Failed to get shared key: {str(e)}") from e

    @staticmethod
    async def get_ecc_key(client: BleakClient) -> bytes:
        """Exchange keys using ECC."""

        try:
            # Generate private key and get public key
            private_key = SigningKey.generate(curve=SECP128r1)
            received_pubkey = []
            public_key = private_key.get_verifying_key()
            pub_x = public_key.pubkey.point.x().to_bytes(16, "little")
            pub_y = public_key.pubkey.point.y().to_bytes(16, "little")

            # Set up notification handler for receiving device's public key
            notification_event = asyncio.Event()

            def notification_handler(data):
                received_pubkey.append(data)
                if len(received_pubkey) == 2:
                    notification_event.set()

            # Exchange public keys
            await client.start_notify(DeviceKeyUUID.ECC.value, notification_handler)
            await client.write_gatt_char(DeviceKeyUUID.ECC.value, pub_x)
            await client.write_gatt_char(DeviceKeyUUID.ECC.value, pub_y)

            # Wait for device's public key with timeout
            await asyncio.wait_for(notification_event.wait(), timeout=10.0)
            await client.stop_notify(DeviceKeyUUID.ECC.value)

            # Compute shared key
            rec_key_point = Point(
                SECP128r1.curve,
                int.from_bytes(received_pubkey[0], "little"),
                int.from_bytes(received_pubkey[1], "little"),
            )
            shared_point = private_key.privkey.secret_multiplier * rec_key_point
            shared_key = int.to_bytes(shared_point.x(), 16, "little")

            logger.debug(f"({client.address}) ECC key exchange successful")
            return shared_key

        except asyncio.TimeoutError:
            raise UtecEncryptionError(f"({client.address}) ECC key exchange timed out")
        except Exception as e:
            raise UtecEncryptionError(f"({client.address}) Failed to update ECC key: {str(e)}") from e

    @staticmethod
    async def get_md5_key(client: BleakClient) -> bytes:
        """Generate key using MD5."""

        try:
            # Read the device secret
            secret = await client.read_gatt_char(DeviceKeyUUID.MD5.value)
            logger.debug(f"({client.address}) Secret: {secret.hex()}")

            if len(secret) != 16:
                raise ValueError(f"({client.address}) Expected secret of length 16, got {len(secret)}")

            # Extract parts from secret
            part1 = struct.unpack("<Q", secret[:8])[0]  # Little-endian
            part2 = struct.unpack("<Q", secret[8:])[0]

            # Apply the MD5 algorithm with magic values
            md5_key = UtecKeyExchange._apply_md5_algorithm(part1, part2)

            logger.debug(f"({client.address}) MD5 key:{md5_key.hex()}")
            return md5_key

        except Exception as e:
            raise UtecEncryptionError(f"({client.address}) Failed to generate MD5 key: {str(e)}") from e

    @staticmethod
    def _apply_md5_algorithm(part1: int, part2: int) -> bytes:
        """Apply the MD5 key generation algorithm using vendor magic values."""

        # Magic string "ULtraloq" in little-endian representation
        magic_value = 0x716F6C6172744C55

        # XOR operations
        xor_val1 = part1 ^ magic_value

        # Compute each byte of xor_val2
        xor_val2_parts = []
        magic_bytes = [0x71, 0x6F, 0x6C, 0x61, 0x72, 0x74, 0x4C, 0x55]  # "ULtraloq"

        for i in range(8):
            shift = 56 - (i * 8)
            part1_byte = (part1 >> shift) & 0xFF
            part2_byte = (part2 >> shift) & 0xFF
            xor_val2_parts.append((part2_byte ^ part1_byte ^ magic_bytes[i]) << shift)

        xor_val2 = sum(xor_val2_parts)

        # Pack the XOR results and compute MD5
        xor_result = struct.pack("<QQ", xor_val1, xor_val2)

        m = hashlib.md5()
        m.update(xor_result)
        result = m.digest()

        # Additional MD5 if needed
        bVar2 = (part1 & 0xFF) ^ 0x55
        if bVar2 & 1:
            m = hashlib.md5()
            m.update(result)
            result = m.digest()

        return result