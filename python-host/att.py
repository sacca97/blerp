from dataclasses import dataclass
from enum import Enum
from typing import Optional
import time
import struct

from constants import *
from helpers import l2cap_send, BluetoothSocket
from scapy.layers.bluetooth import *
from scapy.packet import Raw


class HIDProfile(Enum):
    KEYBOARD = 1
    MOUSE = 2


# HID Report Descriptors
KEYBOARD_REPORT_DESC = bytes.fromhex(
    "05010906a101050719e029e71500250175019508810295017508810105071900"
    "29ff150025ff950675088100c0"
)

MOUSE_REPORT_DESC = bytes.fromhex(
    "05010902a1010901a1000509190129031500250175019503810275059501810105"
    "010930093109381581257f750895038106c0c0"
)

# HID Keyboard modifier keys
MOD_LEFT_CTRL = 0x01
MOD_LEFT_SHIFT = 0x02
MOD_LEFT_ALT = 0x04
MOD_LEFT_GUI = 0x08
MOD_RIGHT_CTRL = 0x10
MOD_RIGHT_SHIFT = 0x20
MOD_RIGHT_ALT = 0x40
MOD_RIGHT_GUI = 0x80

# USB HID Keycodes (subset)
USB_KEY_MAP = {
    "a": 0x04,
    "b": 0x05,
    "c": 0x06,
    "d": 0x07,
    "e": 0x08,
    "f": 0x09,
    "g": 0x0A,
    "h": 0x0B,
    "i": 0x0C,
    "j": 0x0D,
    "k": 0x0E,
    "l": 0x0F,
    "m": 0x10,
    "n": 0x11,
    "o": 0x12,
    "p": 0x13,
    "q": 0x14,
    "r": 0x15,
    "s": 0x16,
    "t": 0x17,
    "u": 0x18,
    "v": 0x19,
    "w": 0x1A,
    "x": 0x1B,
    "y": 0x1C,
    "z": 0x1D,
    "1": 0x1E,
    "2": 0x1F,
    "3": 0x20,
    "4": 0x21,
    "5": 0x22,
    "6": 0x23,
    "7": 0x24,
    "8": 0x25,
    "9": 0x26,
    "0": 0x27,
    "\n": 0x28,
    "\r": 0x28,
    " ": 0x2C,
    "-": 0x2D,
    "=": 0x2E,
    "[": 0x2F,
    "]": 0x30,
    "\\": 0x31,
    ";": 0x33,
    "'": 0x34,
    "`": 0x35,
    ",": 0x36,
    ".": 0x37,
    "/": 0x38,
}

# Shifted keys
SHIFT_MAP = {
    "A": ("a", MOD_LEFT_SHIFT),
    "B": ("b", MOD_LEFT_SHIFT),
    "C": ("c", MOD_LEFT_SHIFT),
    "D": ("d", MOD_LEFT_SHIFT),
    "E": ("e", MOD_LEFT_SHIFT),
    "F": ("f", MOD_LEFT_SHIFT),
    "G": ("g", MOD_LEFT_SHIFT),
    "H": ("h", MOD_LEFT_SHIFT),
    "I": ("i", MOD_LEFT_SHIFT),
    "J": ("j", MOD_LEFT_SHIFT),
    "K": ("k", MOD_LEFT_SHIFT),
    "L": ("l", MOD_LEFT_SHIFT),
    "M": ("m", MOD_LEFT_SHIFT),
    "N": ("n", MOD_LEFT_SHIFT),
    "O": ("o", MOD_LEFT_SHIFT),
    "P": ("p", MOD_LEFT_SHIFT),
    "Q": ("q", MOD_LEFT_SHIFT),
    "R": ("r", MOD_LEFT_SHIFT),
    "S": ("s", MOD_LEFT_SHIFT),
    "T": ("t", MOD_LEFT_SHIFT),
    "U": ("u", MOD_LEFT_SHIFT),
    "V": ("v", MOD_LEFT_SHIFT),
    "W": ("w", MOD_LEFT_SHIFT),
    "X": ("x", MOD_LEFT_SHIFT),
    "Y": ("y", MOD_LEFT_SHIFT),
    "Z": ("z", MOD_LEFT_SHIFT),
    "!": ("1", MOD_LEFT_SHIFT),
    "@": ("2", MOD_LEFT_SHIFT),
    "#": ("3", MOD_LEFT_SHIFT),
    "$": ("4", MOD_LEFT_SHIFT),
    "%": ("5", MOD_LEFT_SHIFT),
    "^": ("6", MOD_LEFT_SHIFT),
    "&": ("7", MOD_LEFT_SHIFT),
    "*": ("8", MOD_LEFT_SHIFT),
    "(": ("9", MOD_LEFT_SHIFT),
    ")": ("0", MOD_LEFT_SHIFT),
    "_": ("-", MOD_LEFT_SHIFT),
    "+": ("=", MOD_LEFT_SHIFT),
    "{": ("[", MOD_LEFT_SHIFT),
    "}": ("]", MOD_LEFT_SHIFT),
    "|": ("\\", MOD_LEFT_SHIFT),
    ":": (";", MOD_LEFT_SHIFT),
    '"': ("'", MOD_LEFT_SHIFT),
    "~": ("`", MOD_LEFT_SHIFT),
    "<": (",", MOD_LEFT_SHIFT),
    ">": (".", MOD_LEFT_SHIFT),
    "?": ("/", MOD_LEFT_SHIFT),
}


@dataclass
class Attribute:
    handle: int
    type_uuid: int
    value: bytes
    permissions: int  # 0x01=read, 0x02=write
    requires_encryption: bool = False
    properties: int = 0  # For characteristics: notify, indicate, etc.


class GATTDatabase:
    def __init__(self):
        self.attributes: dict[int, Attribute] = {}
        self.cccd_state: dict[int, int] = {}  # handle → notification config
        self.next_handle = 1
        self.service_ranges: list[tuple[int, int, int]] = []  # (start, end, uuid)
        self.characteristic_handles: dict[int, int] = {}  # decl_handle → value_handle

    def add_attribute(
        self,
        type_uuid: int,
        value: bytes,
        permissions: int,
        requires_encryption: bool = False,
        properties: int = 0,
    ) -> int:
        handle = self.next_handle
        self.next_handle += 1
        attr = Attribute(
            handle, type_uuid, value, permissions, requires_encryption, properties
        )
        self.attributes[handle] = attr
        return handle

    def add_service(self, uuid: int, primary: bool = True) -> int:
        service_uuid = 0x2800 if primary else 0x2801
        value = struct.pack("<H", uuid)
        start_handle = self.next_handle
        handle = self.add_attribute(service_uuid, value, 0x01)
        self.service_ranges.append((start_handle, start_handle, uuid))
        return handle

    def add_characteristic(
        self,
        uuid: int,
        properties: int,
        value: bytes,
        permissions: int,
        requires_encryption: bool = False,
    ) -> tuple[int, int]:
        # Characteristic declaration
        decl_handle = self.next_handle
        value_handle = self.next_handle + 1

        # Declaration value: properties(1) + value_handle(2) + uuid(2)
        decl_value = struct.pack("<BHH", properties, value_handle, uuid)
        self.add_attribute(0x2803, decl_value, 0x01)

        # Characteristic value
        val_handle = self.add_attribute(
            uuid, value, permissions, requires_encryption, properties
        )

        self.characteristic_handles[decl_handle] = val_handle

        # Update service range end handle
        if self.service_ranges:
            start, _, svc_uuid = self.service_ranges[-1]
            self.service_ranges[-1] = (start, val_handle, svc_uuid)

        return decl_handle, val_handle

    def add_descriptor(
        self,
        uuid: int,
        value: bytes,
        permissions: int,
        requires_encryption: bool = False,
    ) -> int:
        handle = self.add_attribute(uuid, value, permissions, requires_encryption)

        # Update service range
        if self.service_ranges:
            start, _, svc_uuid = self.service_ranges[-1]
            self.service_ranges[-1] = (start, handle, svc_uuid)

        return handle

    def get_attribute(self, handle: int) -> Optional[Attribute]:
        return self.attributes.get(handle)

    def find_by_type_value(
        self, start: int, end: int, attr_type: int, value: bytes
    ) -> list[int]:
        results = []
        for handle in range(start, min(end + 1, self.next_handle)):
            attr = self.attributes.get(handle)
            if attr and attr.type_uuid == attr_type and attr.value == value:
                results.append(handle)
        return results


class ATTManager:
    def __init__(self, device=None, profile: HIDProfile = HIDProfile.KEYBOARD):
        self.device = device
        self.profile = profile
        self.mtu = 23
        self.db = GATTDatabase()
        self.report_handle = None  # Will be set during DB build
        self._build_hid_database()

    def print_database(self):
        """Print the GATT database for debugging"""
        import logging

        logging.info("=== GATT Database ===")
        for handle, attr in sorted(self.db.attributes.items()):
            uuid_str = f"0x{attr.type_uuid:04X}"
            logging.info(
                f"  Handle {handle:3d}: UUID={uuid_str}, value={attr.value.hex()[:40]}, perm=0x{attr.permissions:02X}, enc={attr.requires_encryption}"
            )
        logging.info(f"=== CCCD States ===")
        for handle, state in self.db.cccd_state.items():
            logging.info(f"  Handle {handle}: {state:#x}")
        logging.info("=== Service Ranges ===")
        for start, end, uuid in self.db.service_ranges:
            logging.info(f"  Service 0x{uuid:04X}: handles {start}-{end}")

    def _build_hid_database(self):
        # Generic Access Service (0x1800)
        self.db.add_service(0x1800)
        device_name = (
            f"BLE {'Keyboard' if self.profile == HIDProfile.KEYBOARD else 'Mouse'} v2"
        )
        self.db.add_characteristic(
            0x2A00, 0x02, device_name.encode("utf-8"), 0x01  # Device Name  # Read
        )

        # Appearance
        appearance = 961 if self.profile == HIDProfile.KEYBOARD else 962
        self.db.add_characteristic(
            0x2A01, 0x02, struct.pack("<H", appearance), 0x01  # Read
        )

        # Device Information Service (0x180A)
        self.db.add_service(0x180A)
        self.db.add_characteristic(
            0x2A50,  # PnP ID
            0x02,  # Read
            bytes([0x02, 0x34, 0x12, 0x23, 0xB0, 0x13, 0x00]),  # Vendor/Product
            0x01,
        )

        # Battery Service (0x180F)
        self.db.add_service(0x180F)
        self.db.add_characteristic(
            0x2A19, 0x02, bytes([100]), 0x01  # Battery Level  # Read
        )

        # HID Service (0x1812)
        self.db.add_service(0x1812)

        # Protocol Mode
        self.db.add_characteristic(
            0x2A4E,
            0x06,  # Read/Write
            bytes([0x01]),  # Report mode
            0x03,
            requires_encryption=True,
        )

        # Report Map - Allow reading without encryption for service discovery
        report_desc = (
            KEYBOARD_REPORT_DESC
            if self.profile == HIDProfile.KEYBOARD
            else MOUSE_REPORT_DESC
        )
        self.db.add_characteristic(
            0x2A4B,
            0x02,  # Read
            report_desc,
            0x01,
            requires_encryption=False,  # Allow discovery before encryption
        )

        # HID Information - Allow reading without encryption for service discovery
        self.db.add_characteristic(
            0x2A4A,
            0x02,  # Read
            bytes([0x11, 0x01, 0x00, 0x02]),  # bcdHID, country, flags
            0x01,
            requires_encryption=False,  # Allow discovery before encryption
        )

        # HID Control Point
        self.db.add_characteristic(
            0x2A4C,
            0x04,  # Write without response
            bytes([0x00]),
            0x02,
            requires_encryption=True,
        )

        # Report (Input)
        report_size = 8 if self.profile == HIDProfile.KEYBOARD else 4
        decl_handle, val_handle = self.db.add_characteristic(
            0x2A4D,
            0x12,  # Read + Notify
            bytes(report_size),
            0x01,
            requires_encryption=True,
        )
        self.report_handle = val_handle

        # Client Characteristic Configuration Descriptor (CCCD)
        cccd_handle = self.db.add_descriptor(
            0x2902, bytes([0x00, 0x00]), 0x03, requires_encryption=True  # Read/Write
        )
        self.db.cccd_state[cccd_handle] = 0

        # Report Reference Descriptor
        self.db.add_descriptor(
            0x2908,
            bytes([0x00, 0x01]),  # Report ID 0, Input report
            0x01,
            requires_encryption=True,
        )

    def send(self, sock: BluetoothSocket, handle: int, pkt: Packet):
        l2cap_send(sock, handle, cmd=ATT_Hdr() / pkt, cid=BLE_L2CAP_CID_ATT)

    def check_security(self, attr: Attribute) -> Optional[int]:
        if attr.requires_encryption and self.device and not self.device.encrypted:
            return 0x0F  # Insufficient Encryption
        return None

    def on_message_rx(self, sock: BluetoothSocket, handle: int, pkt: Packet):
        import logging

        # Log ALL ATT requests for debugging
        att_layer_names = [
            layer.__name__
            for layer in pkt.layers()
            if layer.__name__.startswith("ATT_")
        ]
        if att_layer_names:
            logging.info(f"ATT Request: {', '.join(att_layer_names)}")

        if ATT_Exchange_MTU_Request in pkt:
            client_mtu = pkt[ATT_Exchange_MTU_Request].mtu
            # Effective MTU is minimum of client and server, with 23 byte minimum
            self.mtu = max(23, min(client_mtu, self.mtu))
            logging.debug(
                f"ATT_Exchange_MTU_Request: client_mtu={client_mtu}, effective_mtu={self.mtu}"
            )
            self.send(sock, handle, ATT_Exchange_MTU_Response(mtu=self.mtu))

        elif ATT_Find_By_Type_Value_Request in pkt:
            req = pkt[ATT_Find_By_Type_Value_Request]
            start = req.start
            end = req.end
            attr_type = req.uuid
            req_value = bytes(req.data)
            logging.info(
                f"ATT_Find_By_Type_Value_Request: start={start}, end={end}, type=0x{attr_type:04X}, value={req_value.hex()}"
            )

            data = b""
            # Check service ranges as that's the primary use case for this request
            for svc_start, svc_end, svc_uuid in self.db.service_ranges:
                if svc_start >= start and svc_start <= end:
                    attr = self.db.get_attribute(svc_start)
                    if attr and attr.type_uuid == attr_type and attr.value == req_value:
                        item = struct.pack("<HH", svc_start, svc_end)
                        # Response is Opcode(1) + List of [Handle(2) + EndHandle(2)]
                        if len(data) + len(item) > self.mtu - 1:
                            break
                        data += item

            if data:
                self.send(sock, handle, ATT_Find_By_Type_Value_Response(data))
            else:
                self.send(
                    sock,
                    handle,
                    ATT_Error_Response(
                        request=0x06,
                        handle=start,
                        ecode=0x0A,  # Attribute not found
                    ),
                )

        elif ATT_Read_By_Group_Type_Request in pkt:
            req = pkt[ATT_Read_By_Group_Type_Request]
            start = req.start
            end = req.end
            attr_type = req.uuid
            logging.info(
                f"ATT_Read_By_Group_Type_Request: start={start}, end={end}, uuid=0x{attr_type:04X}"
            )

            if attr_type in [0x2800, 0x2801]:  # Primary/Secondary service
                data = b""
                for svc_start, svc_end, svc_uuid in self.db.service_ranges:
                    if svc_start >= start and svc_start <= end:
                        item = struct.pack("<HHH", svc_start, svc_end, svc_uuid)
                        if len(data) + len(item) > self.mtu - 2:
                            break
                        data += item

                if data:
                    # Construct response: length byte + data
                    response = ATT_Read_By_Group_Type_Response(bytes([6]) + data)
                    self.send(sock, handle, response)
                else:
                    self.send(
                        sock,
                        handle,
                        ATT_Error_Response(
                            request=0x10,
                            handle=start,
                            ecode=0x0A,  # Attribute not found
                        ),
                    )
            else:
                self.send(
                    sock,
                    handle,
                    ATT_Error_Response(
                        request=0x10, handle=start, ecode=0x06  # Request not supported
                    ),
                )

        elif ATT_Read_By_Type_Request in pkt:
            req = pkt[ATT_Read_By_Type_Request]
            start = req.start
            end = req.end
            attr_type = req.uuid
            logging.info(
                f"ATT_Read_By_Type_Request: start={start}, end={end}, type=0x{attr_type:04X}"
            )

            data = b""
            item_len = 0
            for h in range(start, min(end + 1, self.db.next_handle)):
                attr = self.db.get_attribute(h)
                if attr and attr.type_uuid == attr_type:
                    # Check security
                    err = self.check_security(attr)
                    if err:
                        self.send(
                            sock,
                            handle,
                            ATT_Error_Response(request=0x08, handle=h, ecode=err),
                        )
                        return

                    # Add attribute data
                    item = struct.pack("<H", h) + attr.value
                    if not data:
                        data = item
                        item_len = len(item)
                    elif len(item) == item_len:
                        if len(data) + len(item) > self.mtu - 2:
                            break
                        data += item
                    else:
                        break

            if data:
                # Construct response: length byte + data
                response = ATT_Read_By_Type_Response(bytes([item_len]) + data)
                self.send(sock, handle, response)
            else:
                self.send(
                    sock,
                    handle,
                    ATT_Error_Response(request=0x08, handle=start, ecode=0x0A),
                )

        elif ATT_Find_Information_Request in pkt:
            req = pkt[ATT_Find_Information_Request]
            start = req.start
            end = req.end
            logging.info(f"ATT_Find_Information_Request: start={start}, end={end}")

            data = b""
            fmt = 1  # 16-bit UUIDs
            for h in range(start, min(end + 1, self.db.next_handle)):
                attr = self.db.get_attribute(h)
                if attr:
                    data += struct.pack("<HH", h, attr.type_uuid)
                    if len(data) >= self.mtu - 2:
                        break

            if data:
                # Construct response: format byte + data
                response = ATT_Find_Information_Response(bytes([fmt]) + data)
                self.send(sock, handle, response)
            else:
                self.send(
                    sock,
                    handle,
                    ATT_Error_Response(request=0x04, handle=start, ecode=0x0A),
                )

        elif ATT_Read_Request in pkt:
            req = pkt[ATT_Read_Request]
            attr_handle = req.gatt_handle
            attr = self.db.get_attribute(attr_handle)
            logging.info(f"ATT_Read_Request: handle={attr_handle}")

            if not attr:
                logging.error(f"ATT_Read_Request: Handle {attr_handle} not found")
                self.send(
                    sock,
                    handle,
                    ATT_Error_Response(
                        request=0x0A, handle=attr_handle, ecode=0x01  # Invalid handle
                    ),
                )
                return

            err = self.check_security(attr)
            if err:
                logging.error(
                    f"ATT_Read_Request: Security check failed for handle {attr_handle} (err={err})"
                )
                self.send(
                    sock,
                    handle,
                    ATT_Error_Response(request=0x0A, handle=attr_handle, ecode=err),
                )
                return

            # Truncate value to MTU-1
            value = attr.value[: self.mtu - 1]
            logging.info(
                f"ATT_Read_Request: Sending response for handle {attr_handle} (len={len(value)})"
            )
            # Small delay to ensure host is ready to receive
            time.sleep(0.01)
            self.send(sock, handle, ATT_Read_Response(value=value))

        elif ATT_Read_Blob_Request in pkt:
            req = pkt[ATT_Read_Blob_Request]
            attr_handle = req.gatt_handle
            offset = req.offset
            attr = self.db.get_attribute(attr_handle)
            logging.info(
                f"ATT_Read_Blob_Request: handle={attr_handle}, offset={offset}"
            )

            if not attr:
                self.send(
                    sock,
                    handle,
                    ATT_Error_Response(
                        request=0x0C, handle=attr_handle, ecode=0x01  # Invalid handle
                    ),
                )
                return

            err = self.check_security(attr)
            if err:
                self.send(
                    sock,
                    handle,
                    ATT_Error_Response(request=0x0C, handle=attr_handle, ecode=err),
                )
                return

            if offset >= len(attr.value):
                self.send(
                    sock,
                    handle,
                    ATT_Error_Response(
                        request=0x0C,
                        handle=attr_handle,
                        ecode=0x07,  # Invalid Offset
                    ),
                )
                return

            # Calculate remaining length and truncate to MTU-1
            chunk = attr.value[offset : offset + (self.mtu - 1)]
            self.send(sock, handle, ATT_Read_Blob_Response(value=chunk))

        elif ATT_Write_Request in pkt:
            req = pkt[ATT_Write_Request]
            attr_handle = req.gatt_handle
            value = bytes(req.data)
            attr = self.db.get_attribute(attr_handle)
            logging.info(
                f"ATT_Write_Request: handle={attr_handle}, value={value.hex()}"
            )

            if not attr:
                self.send(
                    sock,
                    handle,
                    ATT_Error_Response(request=0x12, handle=attr_handle, ecode=0x01),
                )
                return

            # Check if attribute is writable
            if not (attr.permissions & 0x02):
                self.send(
                    sock,
                    handle,
                    ATT_Error_Response(
                        request=0x12,
                        handle=attr_handle,
                        ecode=0x03,  # Write Not Permitted
                    ),
                )
                return

            err = self.check_security(attr)
            if err:
                self.send(
                    sock,
                    handle,
                    ATT_Error_Response(request=0x12, handle=attr_handle, ecode=err),
                )
                return

            # Update CCCD state if this is a CCCD descriptor
            if attr.type_uuid == 0x2902:
                if len(value) < 2:
                    self.send(
                        sock,
                        handle,
                        ATT_Error_Response(
                            request=0x12,
                            handle=attr_handle,
                            ecode=0x0D,  # Invalid Attribute Value Length
                        ),
                    )
                    return
                cccd_val = struct.unpack("<H", value)[0]
                self.db.cccd_state[attr_handle] = cccd_val
                import logging

                logging.info(
                    f"CCCD write: handle={attr_handle}, value={cccd_val:#x} ({'notifications enabled' if cccd_val & 0x01 else 'disabled'})"
                )

            attr.value = value
            self.send(sock, handle, ATT_Write_Response())

        elif ATT_Write_Command in pkt:
            req = pkt[ATT_Write_Command]
            attr_handle = req.gatt_handle
            value = bytes(req.data)
            attr = self.db.get_attribute(attr_handle)

            # Write Command: check security and permissions, but don't send error responses
            if attr and (attr.permissions & 0x02) and not self.check_security(attr):
                attr.value = value

    def notify(
        self, sock: BluetoothSocket, conn_handle: int, attr_handle: int, value: bytes
    ):
        # Find CCCD for this characteristic by searching descriptors after the value handle
        cccd_handle = None
        for h in range(attr_handle + 1, self.db.next_handle):
            attr = self.db.get_attribute(h)
            if attr is None:
                break
            if attr.type_uuid == 0x2902:  # Found CCCD
                cccd_handle = h
                break
            # Stop if we hit the next service or characteristic declaration
            if attr.type_uuid in [0x2800, 0x2801, 0x2803]:
                break

        cccd_value = self.db.cccd_state.get(cccd_handle, 0) if cccd_handle else 0

        import logging

        logging.info(
            f"Notify: handle={attr_handle}, cccd_handle={cccd_handle}, cccd_value={cccd_value:#x}, value={value.hex()}"
        )

        if not (cccd_value & 0x01):
            logging.warning(
                f"Notifications NOT enabled for handle {attr_handle} (CCCD={cccd_value:#x}) - Sending anyway"
            )

        # Validate/truncate value to fit within MTU
        max_value_len = self.mtu - 3  # opcode(1) + handle(2)
        if len(value) > max_value_len:
            logging.warning(
                f"Truncating notification value from {len(value)} to {max_value_len} bytes"
            )
            value = value[:max_value_len]

        pkt = ATT_Handle_Value_Notification(gatt_handle=attr_handle, value=value)
        # Explicitly set opcode for Notification (0x1B)
        l2cap_send(sock, conn_handle, ATT_Hdr(opcode=0x1B) / pkt, cid=BLE_L2CAP_CID_ATT)
        logging.info(f"Sent notification for handle {attr_handle}")

    # Keyboard API
    def send_key(self, key: str, modifiers: int = 0):
        if self.profile != HIDProfile.KEYBOARD:
            raise RuntimeError("send_key only available for KEYBOARD profile")

        if not self.device or not self.device.sock:
            raise RuntimeError("Device not connected")

        # Handle shifted characters
        if key in SHIFT_MAP:
            base_key, mod = SHIFT_MAP[key]
            keycode = USB_KEY_MAP.get(base_key, 0)
            modifiers |= mod
        else:
            keycode = USB_KEY_MAP.get(key.lower(), 0)

        # Press key
        report = bytes([modifiers, 0, keycode, 0, 0, 0, 0, 0])
        self.send_keyboard_report(report)

        # Release key
        time.sleep(0.05)
        report = bytes([0, 0, 0, 0, 0, 0, 0, 0])
        self.send_keyboard_report(report)

    def send_text(self, text: str, delay: float = 0.05):
        if self.profile != HIDProfile.KEYBOARD:
            raise RuntimeError("send_text only available for KEYBOARD profile")

        for char in text:
            self.send_key(char)
            time.sleep(delay)

    def send_keyboard_report(self, report: bytes):
        if self.profile != HIDProfile.KEYBOARD:
            raise RuntimeError(
                "send_keyboard_report only available for KEYBOARD profile"
            )

        if len(report) != 8:
            raise ValueError("Keyboard report must be 8 bytes")

        if not self.device or not self.device.sock or not self.report_handle:
            raise RuntimeError("Device not connected or report handle not set")

        self.notify(self.device.sock, self.device.handle, self.report_handle, report)

    # Mouse API
    def move_mouse(self, dx: int, dy: int):
        if self.profile != HIDProfile.MOUSE:
            raise RuntimeError("move_mouse only available for MOUSE profile")

        # Clamp to signed 8-bit range
        dx = max(-127, min(127, dx))
        dy = max(-127, min(127, dy))

        report = bytes([0, dx & 0xFF, dy & 0xFF, 0])
        self.send_mouse_report(report)

    def click(self, button: int = 1):
        if self.profile != HIDProfile.MOUSE:
            raise RuntimeError("click only available for MOUSE profile")

        if button < 1 or button > 3:
            raise ValueError("Button must be 1 (left), 2 (right), or 3 (middle)")

        button_mask = 1 << (button - 1)

        # Press
        report = bytes([button_mask, 0, 0, 0])
        self.send_mouse_report(report)

        # Release
        time.sleep(0.01)
        report = bytes([0, 0, 0, 0])
        self.send_mouse_report(report)

    def send_mouse_report(self, report: bytes):
        if self.profile != HIDProfile.MOUSE:
            raise RuntimeError("send_mouse_report only available for MOUSE profile")

        if len(report) != 4:
            raise ValueError("Mouse report must be 4 bytes")

        if not self.device or not self.device.sock or not self.report_handle:
            raise RuntimeError("Device not connected or report handle not set")

        self.notify(self.device.sock, self.device.handle, self.report_handle, report)
