"""Constants for Utecio API Library"""

from enum import Enum

BATTERY_LEVEL = {-1:"Depleted", 0:"Replace", 1:"Low", 2:"Medium", 3:"High"}
LOCK_MODE = {0:"Normal", 1:"Passage Mode", 2:"Lockout Mode"}
BOLT_STATUS = {0: "Unlocked", 1:"Locked", 255:"No Bolt"}
CRC8Table = [0, 94, 188, 226, 97, 63, 221, 131, 194, 156, 126, 32, 163, 253, 31, 65, 157, 195, 33, 127, 252, 162, 64, 30, 95, 1, 227, 189, 62, 96, 130, 220, 35, 125, 159, 193, 66, 28, 254, 160, 225, 191, 93, 3, 128, 222, 60, 98, 190, 224, 2, 92, 223, 129, 99, 61, 124, 34, 192, 158, 29, 67, 161, 255, 70, 24, 250, 164, 39, 121, 155, 197, 132, 218, 56, 102, 229, 187, 89, 7, 219, 133, 103, 57, 186, 228, 6, 88, 25, 71, 165, 251, 120, 38, 196, 154, 101, 59, 217, 135, 4, 90, 184, 230, 167, 249, 27, 69, 198, 152, 122, 36, 248, 166, 68, 26, 153, 199, 37, 123, 58, 100, 134, 216, 91, 5, 231, 185, 140, 210, 48, 110, 237, 179, 81, 15, 78, 16, 242, 172, 47, 113, 147, 205, 17, 79, 173, 243, 112, 46, 204, 146, 211, 141, 111, 49, 178, 236, 14, 80, 175, 241, 19, 77, 206, 144, 114, 44, 109, 51, 209, 143, 12, 82, 176, 238, 50, 108, 142, 208, 83, 13, 239, 177, 240, 174, 76, 18, 145, 207, 45, 115, 202, 148, 118, 40, 171, 245, 23, 73, 8, 86, 180, 234, 105, 55, 213, 139, 87, 9, 235, 181, 54, 104, 138, 212, 149, 203, 41, 119, 244, 170, 72, 22, 233, 183, 85, 11, 136, 214, 52, 106, 43, 117, 151, 201, 74, 20, 246, 168, 116, 42, 200, 150, 21, 75, 169, 247, 182, 232, 10, 84, 215, 137, 107, 53]
BLE_RETRY_DELAY_DEF = 1.5
BLE_RETRY_MAX_DEF = 4

UTEC_DEVICE_PREFIXES = {"UT", "UTEC", "U-Tec", "ULTRALOQ", "U-Bolt",}

UTEC_MANUFACTURER_IDS = {0x02E5, 0x0184}


class DeviceLockModel(Enum):
    UL1BT = "UL1-BT"
    Latch5NFC = "Latch-5-NFC"
    Latch5F = "Latch-5-F"
    BoltNFC = "Bolt-NFC"
    LEVER = "LEVER"
    UBolt = "U-Bolt"
    UBoltWiFi = "U-Bolt-WiFi"
    UBoltZWave = "U-Bolt-ZWave"
    UL3 = "SmartLockByBle"
    UL3_2ND = "UL3-2ND"
    UL300 = "UL300"


class DeviceBatteryLevel(Enum):
    NOTSET = -1
    HIGH = 3
    MEDIUM = 2
    LOW = 1
    CRITICAL = 0
    DEPLETED = -1


class DeviceLockWorkMode(Enum):
    NOTSET = -1
    NORMAL = 0
    PASSAGE = 1
    LOCKOUT = 2


class DeviceLockStatus(Enum):
    NOTSET = -1
    UNAVAILABLE = 0
    UNLOCKED = 1
    LOCKED = 2
    NOTAVAILABLE = 255


class BLECommandCode(Enum):
    LOCK_STATUS = 80
    GET_LOCK_STATUS = 81
    GET_BATTERY = 67
    GET_SN = 94
    GET_MUTE = 83
    UNLOCK = 85
    BOLT_LOCK = 86
    SET_LOCK_STATUS = 82
    REBOOT = 23
    DOORSENSOR = 117
    GET_AUTOLOCK = 90
    SET_AUTOLOCK = 89
    SET_WORK_MODE = 160
    ADMIN_LOGIN = 32
    READ_TIME = 65
    WRITE_TIME = 66


class BleResponseCode(Enum):
    LOCK_STATUS = 208
    GET_LOCK_STATUS = 209
    GET_BATTERY = 195
    UNLOCK = 213
    BOLT_LOCK = 214
    SET_LOCK_STATUS = 210
    GET_SN = 222
    GET_MUTE = 211
    DOORSENSOR = 245
    SET_AUTOLOCK = 217
    GET_AUTOLOCK = 218
    SET_WORK_MODE = 32
    ADMIN_LOGIN = 160
    READ_TIME = 193
    WRITE_TIME = 194


class DeviceServiceUUID(Enum):
    LOCK = "00007200-0000-1000-8000-00805f9b34fb"
    DATA = "00007201-0000-1000-8000-00805f9b34fb"
    BRIDGE = "00002a23-0000-1000-8000-00805f9b34fb"


class DeviceKeyUUID(Enum):
    STATIC = "00007220-0000-1000-8000-00805f9b34fb"
    MD5 = "00007223-0000-1000-8000-00805f9b34fb"
    ECC = "00007221-0000-1000-8000-00805f9b34fb"

# Misc things that might be helpful later

#bleLock: mBleLock \u4e3a\u7a7a
# UUIDUtils: 0000%04x-0000-1000-8000-00805f9b34fb
#REQ_BLE_CODE:I = 0x376
#REQ_BLE_OPEN:I = 0x280
#EcdhApi: anvizecc
#BleLockKey: Anviz.ut

#UUID: 00002902-0000-1000-8000-00805f9b34fb
#ble Connect: \u6b63\u5728\u8fde\u63a5
#UUID_SERVICE_UTEC_LOCK: 00007200-0000-1000-8000-00805f9b34fb
#UUID_SERVICE_UTEC_DEVINFO: 0000180A-0000-1000-8000-00805f9b34fb
#UUID_SERVICE_BRIDGE_DEVINFO:
#UUID_CHAR_BRIDGE_MAC: 00002a23-0000-1000-8000-00805f9b34fb
#UUID_CHAR_LOCK_KEY: 00007220-0000-1000-8000-00805f9b34fb
#UUID_CHAR_LOCK_KEY_ECC: 00007221-0000-1000-8000-00805f9b34fb
#UUID_CHAR_LOCK_KEY_MD5: 00007223-0000-1000-8000-00805f9b34fb
#UUID_CHAR_SYSTEM_ID: 00002A23-0000-1000-8000-00805f9b34fb
#UUID_CHAR_MODEL_NUMBER: 00002A24-0000-1000-8000-00805f9b34fb
#UUID_CHAR_FIRMWARE: 00002A26-0000-1000-8000-00805f9b34fb
#UUID_CHAR_SN: 00002A25-0000-1000-8000-00805f9b34fb
#UUID_DESCRIPTOR_CONFIG: 00002902-0000-1000-8000-00805f9b34fb

class BleRequestSchedule(Enum):
    IMMEDIATE = 0
    NEXT_RUN = 1


DEVICE_CONFIGS = {
    'Latch-5-F': {
        'bluetooth': True,
        'autolock': True,
        'update_wifi': True,
        'alerts': True,
        'mutemode': True,
        'doublefp': True,
        'keypad': True,
        'fingprinter': True,
        'needregristerpwd': True,
        'havesn': True,
        'moreadmin': True,
        'timelimit': True,
        'passage': True,
        'lockout': True,
        'bt264': True,
        'keepalive': True,
        'passageautolock': True,
        'singlelatchboltmortic': True,
        'smartphone_nfc': True,
        'bt_close': True
    },
    'Latch-5-NFC': {
        'bluetooth': True,
        'autolock': True,
        'update_wifi': True,
        'alerts': True,
        'mutemode': True,
        'rfid': True,
        'rfid_twice': True,
        'keypad': True,
        'needregristerpwd': True,
        'havesn': True,
        'moreadmin': True,
        'timelimit': True,
        'passage': True,
        'lockout': True,
        'bt264': True,
        'keepalive': True,
        'passageautolock': True,
        'singlelatchboltmortic': True,
        'smartphone_nfc': True,
        'bt_close': True
    },
    'Ultraloq-1': {
        'bluetooth': True,
        'rfid': True,
        'rfid_twice': True,
        'fingprinter': True,
        'autobolt': True,
        'update_ota': True,
        'update_oad': True,
        'alerts': True,
        'shakeopen': True,
        'mutemode': True,
        'passage': True,
        'lockout': True,
        'havesn': True,
        'direction': True,
        'keepalive': True,
        'singlelatchboltmortic': True
    },
    'Bolt-NFC': {
        'lock': True,
        'bluetooth': True,
        'autolock': True,
        'update_ota': True,
        'update_wifi': True,
        'direction': True,
        'alerts': True,
        'mutemode': True,
        'manual': True,
        'shakeopen': True,
        'havesn': True,
        'rfid': True,
        'keypad': True,
        'needregristerpwd': True,
        'timelimit': True,
        'moreadmin': True,
        'lockout': True,
        'bt264': True,
        'doorsensor': True,
        'keepalive': True,
        'autounlock': True,
        'smartphone_nfc': True,
        'update_2642': True,
        'isautodirection': True,
        'ishomekit': True
    },
    'Lever': {
        'bluetooth': True,
        'autolock': True,
        'update_ota': True,
        'alerts': True,
        'mutemode': True,
        'shakeopen': True,
        'fingprinter': True,
        'keypad': True,
        'doublefp': True,
        'needregristerpwd': True,
        'havesn': True,
        'moreadmin': True,
        'timelimit': True,
        'passage': True,
        'lockout': True,
        'bt264': True,
        'keepalive': True,
        'passageautolock': True,
        'singlelatchboltmortic': True
    },
    'UBolt': {
        'lock': True,
        'bluetooth': True,
        'autolock': True,
        'autounlock': True,
        'update_ota': True,
        'direction': True,
        'alerts': True,
        'mutemode': True,
        'manual': True,
        'shakeopen': True,
        'havesn': True,
        'moreadmin': True,
        'needreadmodel': True,
        'keypad': True,
        'lockout': True,
        'timelimit': True,
        'needregristerpwd': True,
        'bt264': True,
        'keepalive': True
    },
    'UBolt-Pro': {
        'lock': True,
        'bluetooth': True,
        'autolock': True,
        'autounlock': True,
        'update_ota': True,
        'direction': True,
        'alerts': True,
        'mutemode': True,
        'manual': True,
        'shakeopen': True,
        'havesn': True,
        'moreadmin': True,
        'needreadmodel': True,
        'keypad': True,
        'lockout': True,
        'timelimit': True,
        'needregristerpwd': True,
        'bt264': True,
        'keepalive': True
    },
    'UBolt-Pro-Wifi': {
        'lock': True,
        'bluetooth': True,
        'autolock': True,
        'update_ota': True,
        'update_wifi': True,
        'direction': True,
        'alerts': True,
        'mutemode': True,
        'manual': True,
        'shakeopen': True,
        'havesn': True,
        'needreadmodel': True,
        'keypad': True,
        'needregristerpwd': True,
        'timelimit': True,
        'moreadmin': True,
        'lockout': True,
        'bt264': True,
        'doorsensor': True,
        'keepalive': True,
        'autounlock': True
    },
    'Ubolt-Wifi': {
        'lock': True,
        'bluetooth': True,
        'autolock': True,
        'update_ota': True,
        'update_wifi': True,
        'direction': True,
        'alerts': True,
        'mutemode': True,
        'manual': True,
        'shakeopen': True,
        'havesn': True,
        'needreadmodel': True,
        'keypad': True,
        'needregristerpwd': True,
        'timelimit': True,
        'moreadmin': True,
        'lockout': True,
        'bt264': True,
        'doorsensor': True,
        'keepalive': True,
        'autounlock': True
    },
    'UBolt-ZWave': {
        'lock': True,
        'bluetooth': True,
        'autolock': True,
        'update_ota': True,
        'direction': True,
        'alerts': True,
        'mutemode': True,
        'manual': True,
        'shakeopen': True,
        'havesn': True,
        'needreadmodel': True,
        'keypad': True,
        'needregristerpwd': True,
        'timelimit': True,
        'moreadmin': True,
        'lockout': True,
        'bt264': True,
        'doorsensor': True,
        'keepalive': True,
        'autounlock': True,
        'zwave': True
    },
    'Ultraloq-3': {
        'bluetooth': True,
        'autolock': True,
        'update_ota': True,
        'alerts': True,
        'mutemode': True,
        'shakeopen': True,
        'fingprinter': True,
        'keypad': True,
        'doublefp': True,
        'needregristerpwd': True,
        'havesn': True,
        'locklocal': True,
        'needsycbuser': True,
        'moreadmin': True,
        'customuserid': True,
        'timelimit': True,
        'passage': True,
        'lockout': True,
        'bt264': True,
        'keepalive': True,
        'passageautolock': True,
        'singlelatchboltmortic': True
    },
    'Ultraloq-300': {
        'bluetooth': True,
        'rfid': True,
        'rfid_once': True,
        'keypad': True,
        'fingprinter': True,
        'update_ota': True,
        'update_oad': True,
        'alerts': True,
        'shakeopen': True,
        'mutemode': True,
        'moreadmin': True,
        'timelimit': True,
        'passage': True,
        'lockout': True,
        'morelanguage': True,
        'locklocal': True,
        'needsycbuser': True,
        'havesn': True,
        'keepalive': True,
        'singlelatchboltmortic': True,
        'adduserremovenum': 5
    },
    'Utec-Generic': {
        'bluetooth': True,
        'keypad': True,
        'fingprinter': True,
        'shakeopen': True,
        'morepwd': True,
        'passage': True,
        'lockout': True,
        'locklocal': True,
        'needsycbuser': True,
        'clone': True,
        'customuserid': True,
        'singlelatchboltmortic': True,
        'keepalive': True
    }
}



