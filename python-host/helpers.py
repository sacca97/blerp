import fcntl
import logging
import os
import re
import struct
import sys
from typing import Tuple

from constants import *
from scapy.fields import *
from scapy.layers.bluetooth import *
from scapy.packet import *

mac_regex = r"^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$"


def is_valid_mac(s: str):

    if re.fullmatch(mac_regex, s):
        return True
    return False


class BluetoothSocket(BluetoothUserSocket):
    def send_command(self, cmd):
        opcode = cmd[HCI_Command_Hdr].opcode
        self.send(cmd)
        while True:
            r = self.recv()
            if r.type == 0x04 and r.code in (0x0E, 0x0F) and r.opcode == opcode:
                if hasattr(r, "status") and r.status != 0:
                    raise BluetoothCommandError(
                        f"Command {cmd.summary()} failed with {r.status}"
                    )  # noqa: E501
                return r

    def wait_event(self, evt):
        events = evt if isinstance(evt, list) else [evt]
        while True:
            pkt = self.recv()
            if HCI_Event_Hdr not in pkt:
                continue
            for event in events:
                if event in pkt:
                    status = getattr(pkt, "status", 0)
                    return pkt if status == 0 else None


# def hci_cmd_get(cmd):
#     return HCI_Hdr() / HCI_Command_Hdr() / cmd


class HCI_Cmd_LE_Set_Public_Address(Packet):
    name = "LE Set Public Address"
    fields_desc = [LEMACField("addr", None)]


class HCI_Cmd_LE_Custom_Command(Packet):
    name = "LE Custom Command"
    fields_desc = [LEShortField("opcode", 0)]


# # class SM_Security_Request(Packet):
# #     name = "Security Request"
# #     fields_desc = [BitField("authentication", 0, 8)]


# class HCI_Cmd_LE_Set_Event_Mask(Packet):
#     name = "HCI_LE_Set_Event_Mask"
#     fields_desc = [
#         StrFixedLenField("mask", b"\xff\x1f\x0a\x03\x00\x00\x00\x00", 8)
#     ]  # noqa: E501


# class HCI_Cmd_LE_Set_Extended_Scan_Parameters(Packet):
#     name = "HCI_LE_Set_Extended_Scan_Parameters"
#     fields_desc = [
#         ByteEnumField(
#             "oatype",
#             0,
#             {0: "public", 1: "random", 2: "rpa_pub", 3: "rpa_rand"},
#         ),
#         ByteEnumField(
#             "scanning_filter_policy",
#             0,
#             {0: "basic", 1: "whitelist", 2: "basic_rpa", 3: "whitelist_rpa"},
#         ),
#         # This field controls which of the following blocks appear
#         ByteField("scanning_phys", 0x01),  # Default 0x01 (1M only)
#         # --- LE 1M PHY (Bit 0) ---
#         ConditionalField(
#             ByteEnumField("scan_type_1m", 1, {0: "passive", 1: "active"}),
#             lambda pkt: pkt.scanning_phys & 0x01,
#         ),
#         ConditionalField(
#             LEShortField("scan_interval_1m", 0x0010),
#             lambda pkt: pkt.scanning_phys & 0x01,
#         ),
#         ConditionalField(
#             LEShortField("scan_window_1m", 0x0010), lambda pkt: pkt.scanning_phys & 0x01
#         ),
#         # --- LE Coded PHY (Bit 2) ---
#         ConditionalField(
#             ByteEnumField("scan_type_coded", 1, {0: "passive", 1: "active"}),
#             lambda pkt: pkt.scanning_phys & 0x04,
#         ),
#         ConditionalField(
#             LEShortField("scan_interval_coded", 0x0010),
#             lambda pkt: pkt.scanning_phys & 0x04,
#         ),
#         ConditionalField(
#             LEShortField("scan_window_coded", 0x0010),
#             lambda pkt: pkt.scanning_phys & 0x04,
#         ),
#     ]


# # class HCI_Cmd_LE_Set_Extended_Scan_Parameters(Packet):
# #     name = "HCI_LE_Set_Extended_Scan_Parameters"
# #     fields_desc = [
# #         # 1. Own Address Type (0x01 = Random)
# #         ByteEnumField(
# #             "atype",
# #             0,
# #             {0: "public", 1: "random", 2: "rpa (pub)", 3: "rpa (random)"},
# #         ),
# #         # 2. Filter Policy (0x00 = Accept all)
# #         ByteEnumField(
# #             "policy",
# #             0,
# #             {0: "all", 1: "whitelist", 2: "undirected_rpa", 3: "whitelist_rpa"},
# #         ),
# #         # 3. PHYs (0x05 = 1M (bit 0) | Coded (bit 2))
# #         # Note: If you change this value, you technically need to add/remove the
# #         # config blocks below. This structure assumes 0x05.
# #         ByteField("scanning_phys", 0x01),
# #         # --- Entry 0: LE 1M Config ---
# #         ByteEnumField("type", 0, {0: "passive", 1: "active"}),
# #         XLEShortField("interval", 0x0012),  # 22.5 ms
# #         XLEShortField("window", 0x0012),  # 11.25 ms
# #         # --- Entry 1: LE Coded Config ---
# #         # Note: These fields only exist because bit 2 was set in scanning_phys
# #         # ByteEnumField("type_coded", 1, {0: "passive", 1: "active"}),
# #         # XLEShortField("interval_coded", 0x006C),  # 67.5 ms
# #         # XLEShortField("window_coded", 0x0036),  # 33.75 ms
# #     ]


# class HCI_Cmd_LE_Set_Extended_Scan_Enable(Packet):
#     name = "HCI_LE_Set_Extended_Scan_Enable"
#     fields_desc = [
#         ByteEnumField("enable", 1, {0: "disabled", 1: "enabled"}),
#         ByteEnumField(
#             "filter_dups", 1, {0: "disabled", 1: "enabled", 2: "reset_period"}
#         ),
#         # 0x0000: Continuous scan until explicitly disabled.
#         LEShortField("duration", 500),  # Default: scan for 5 seconds
#         # 0x0000: No periodic scanning (Standard behavior).
#         # If Duration is 0, this MUST be 0. Unit: 1.28s.
#         LEShortField("period", 0),
#     ]


# # --- 1. Define the Parameters Command (Opcode 0x2036) ---
# class HCI_Cmd_LE_Set_Extended_Advertising_Parameters(Packet):
#     name = "HCI_LE_Set_Extended_Advertising_Parameters"
#     fields_desc = [
#         ByteField("handle", 0),
#         # Properties default 0x0013 is "Connectable+Scannable+Legacy"
#         LEShortField("properties", 0x0013),
#         LEThreeBytesField("pri_interval_min", 160),  # 100ms (3 bytes per BT spec)
#         LEThreeBytesField("pri_interval_max", 160),  # 100ms (3 bytes per BT spec)
#         ByteField("pri_channel_map", 7),  # 37, 38, 39
#         ByteEnumField("oatype", 0, {0: "public", 1: "random"}),
#         ByteEnumField("patype", 0, {0: "public", 1: "random"}),
#         LEMACField("paddr", None),
#         ByteEnumField("filter_policy", 0, {0: "all"}),
#         SignedByteField("tx_power", 127),  # 127 = No preference
#         # PHY Configuration
#         ByteEnumField("pri_phy", 1, {1: "1M", 3: "Coded"}),  # Primary PHY
#         ByteField("sec_max_skip", 0),
#         ByteEnumField("sec_phy", 1, {1: "1M", 2: "2M", 3: "Coded"}),  # Secondary PHY
#         ByteField("sid", 0),
#         ByteField("scan_req_notify_enable", 0),
#     ]


# bind_layers(
#     HCI_Command_Hdr,
#     HCI_Cmd_LE_Set_Extended_Advertising_Parameters,
#     ogf=0x08,
#     ocf=0x0036,
# )


# # --- LE Extended Create Connection (Opcode 0x2043) ---
# # class HCI_Cmd_LE_Extended_Create_Connection(Packet):
# #     name = "HCI_LE_Extended_Create_Connection"
# #     fields_desc = [
# #         # Initiator_Filter_Policy
# #         ByteEnumField("filter", 0, {0: "peer_addr", 1: "filter_accept_list"}),
# #         # Own_Address_Type
# #         ByteEnumField(
# #             "atype", 0, {0: "public", 1: "random", 2: "rpa_pub", 3: "rpa_random"}
# #         ),
# #         # Peer_Address_Type
# #         ByteEnumField("patype", 0, {0: "public", 1: "random"}),
# #         # Peer_Address
# #         LEMACField("paddr", None),
# #         # Initiating_PHYs (bit 0=1M, bit 1=2M, bit 2=Coded)
# #         ByteField("init_phys", 0x01),
# #         # --- PHY parameters for LE 1M (when bit 0 set) ---
# #         LEShortField("scan_interval", 96),
# #         LEShortField("scan_window", 96),
# #         LEShortField("min_interval", 40),
# #         LEShortField("max_interval", 80),
# #         LEShortField("latency", 0),
# #         LEShortField("timeout", 500),
# #         LEShortField("min_ce", 0),
# #         LEShortField("max_ce", 0),
# #         # Note: Add additional blocks for 2M/Coded if init_phys includes those bits
# #     ]


# class HCI_Cmd_LE_Extended_Create_Connection(Packet):
#     name = "HCI_LE_Extended_Create_Connection"
#     fields_desc = [
#         ByteEnumField("filter_policy", 0, {0: "peer_addr", 1: "accept_list"}),
#         ByteEnumField(
#             "atype", 0, {0: "public", 1: "random", 2: "rpa_pub", 3: "rpa_rand"}
#         ),
#         ByteEnumField(
#             "patype", 0, {0: "public", 1: "random", 2: "rpa_pub", 3: "rpa_rand"}
#         ),
#         # 4. Peer Address
#         LEMACField("paddr", None),
#         # Bit 0: 1M, Bit 1: 2M, Bit 2: Coded
#         ByteField("phys", 1),
#         # --- PHY 1M Parameters (Bit 0) ---
#         ConditionalField(
#             LEShortField("interval_1m", 96), lambda pkt: pkt.initiating_phys & 1
#         ),
#         ConditionalField(
#             LEShortField("window_1m", 96), lambda pkt: pkt.initiating_phys & 1
#         ),
#         ConditionalField(
#             LEShortField("min_interval_1m", 40),
#             lambda pkt: pkt.initiating_phys & 1,
#         ),
#         ConditionalField(
#             LEShortField("max_interval_1m", 56),
#             lambda pkt: pkt.initiating_phys & 1,
#         ),
#         ConditionalField(
#             LEShortField("latency_1m", 0), lambda pkt: pkt.initiating_phys & 1
#         ),
#         ConditionalField(
#             LEShortField("timeout_1m", 42), lambda pkt: pkt.initiating_phys & 1
#         ),  # 420ms
#         ConditionalField(
#             LEShortField("min_ce_1m", 0), lambda pkt: pkt.initiating_phys & 1
#         ),
#         ConditionalField(
#             LEShortField("max_ce_1m", 0), lambda pkt: pkt.initiating_phys & 1
#         ),
#         # --- PHY Coded Parameters (Bit 2) ---
#         ConditionalField(
#             LEShortField("interval_coded", 96), lambda pkt: pkt.initiating_phys & 4
#         ),
#         ConditionalField(
#             LEShortField("window_coded", 96), lambda pkt: pkt.initiating_phys & 4
#         ),
#         ConditionalField(
#             LEShortField("min_interval_coded", 40),
#             lambda pkt: pkt.initiating_phys & 4,
#         ),
#         ConditionalField(
#             LEShortField("max_interval_coded", 56),
#             lambda pkt: pkt.initiating_phys & 4,
#         ),
#         ConditionalField(
#             LEShortField("latency_coded", 0), lambda pkt: pkt.initiating_phys & 4
#         ),
#         ConditionalField(
#             LEShortField("timeout_coded", 42), lambda pkt: pkt.initiating_phys & 4
#         ),
#         ConditionalField(
#             LEShortField("min_ce_coded", 0), lambda pkt: pkt.initiating_phys & 4
#         ),
#         ConditionalField(
#             LEShortField("max_ce_coded", 0), lambda pkt: pkt.initiating_phys & 4
#         ),
#     ]


# bind_layers(
#     HCI_Command_Hdr, HCI_Cmd_LE_Extended_Create_Connection, ogf=0x08, ocf=0x0043
# )


# # --- LE Enhanced Connection Complete Event (Subevent 0x0A) ---
# class HCI_LE_Meta_Enhanced_Connection_Complete(Packet):
#     name = "LE Enhanced Connection Complete"
#     fields_desc = [
#         ByteEnumField("status", 0, {0: "success"}),
#         LEShortField("handle", 0),
#         ByteEnumField("role", 0, {0: "central", 1: "peripheral"}),
#         ByteEnumField(
#             "patype",
#             0,
#             {0: "public", 1: "random", 2: "public_identity", 3: "random_identity"},
#         ),
#         LEMACField("paddr", None),
#         LEMACField("local_rpa", None),  # Local Resolvable Private Address
#         LEMACField("peer_rpa", None),  # Peer Resolvable Private Address
#         LEShortField("interval", 54),
#         LEShortField("latency", 0),
#         LEShortField("supervision", 42),
#         ByteEnumField(
#             "master_clock_accuracy",
#             5,
#             {
#                 0: "500ppm",
#                 1: "250ppm",
#                 2: "150ppm",
#                 3: "100ppm",
#                 4: "75ppm",
#                 5: "50ppm",
#                 6: "30ppm",
#                 7: "20ppm",
#             },
#         ),
#     ]

#     def answers(self, other):
#         if HCI_Cmd_LE_Extended_Create_Connection not in other:
#             return False

#         cmd = other[HCI_Cmd_LE_Extended_Create_Connection]

#         return cmd.patype == self.patype and cmd.paddr == self.paddr


# bind_layers(HCI_Event_LE_Meta, HCI_LE_Meta_Enhanced_Connection_Complete, event=0x0A)


# # --- 2. Define the Enable Command (Opcode 0x2039) ---
# # Note: This is different from Legacy Enable! It takes a list of sets.
# # class HCI_Cmd_LE_Set_Extended_Advertise_Enable(Packet):
# #     name = "HCI_LE_Set_Extended_Advertising_Enable"
# #     fields_desc = [
# #         ByteEnumField("enable", 1, {0: "disable", 1: "enable"}),
# #         ByteField("num_sets", 1),
# #         ByteField("handle", 0),
# #         XLEShortField("duration", 0),  # 0 = Continuous
# #         ByteField("max_events", 0),
# #     ]


# class HCI_Ext_Adv_Set(Packet):
#     name = "Extended Advertising Set"
#     fields_desc = [
#         ByteField("handle", 0),
#         LEShortField("duration", 0),
#         ByteField("max_events", 0),
#     ]


# class HCI_Cmd_LE_Set_Extended_Advertise_Enable(Packet):
#     name = "HCI_LE_Set_Extended_Advertising_Enable"
#     fields_desc = [
#         ByteEnumField("enable", 1, {0: "disable", 1: "enable"}),
#         FieldLenField("num_sets", None, count_of="sets", fmt="B"),
#         PacketListField(
#             "sets", [], HCI_Ext_Adv_Set, count_from=lambda pkt: pkt.num_sets
#         ),
#     ]


# bind_layers(
#     HCI_Command_Hdr, HCI_Cmd_LE_Set_Extended_Advertise_Enable, ogf=0x08, ocf=0x0039
# )


# # --- LE Set Advertising Set Random Address (Opcode 0x2035) ---
# class HCI_Cmd_LE_Set_Advertising_Set_Random_Address(Packet):
#     name = "HCI_LE_Set_Advertising_Set_Random_Address"
#     fields_desc = [
#         ByteField("handle", 0),
#         LEMACField("addr", None),
#     ]


# bind_layers(
#     HCI_Command_Hdr,
#     HCI_Cmd_LE_Set_Advertising_Set_Random_Address,
#     ogf=0x08,
#     ocf=0x0035,
# )


# class HCI_Cmd_LE_Set_Extended_Advertising_Data(Packet):
#     name = "HCI_LE_Set_Extended_Advertising_Data"
#     fields_desc = [
#         ByteField("handle", 0),
#         ByteEnumField(
#             "operation",
#             3,
#             {
#                 0: "intermediate_frag",
#                 1: "first_frag",
#                 2: "last_frag",
#                 3: "complete",
#                 4: "unchanged_data",
#             },
#         ),
#         ByteEnumField("frag_pref", 1, {0: "allow_frag", 1: "no_frag"}),
#         FieldLenField("len", None, length_of="data", fmt="B"),
#         PacketListField("data", [], EIR_Hdr, length_from=lambda pkt: pkt.len),
#     ]


# # Bind to Opcode 0x2037
# bind_layers(
#     HCI_Command_Hdr, HCI_Cmd_LE_Set_Extended_Advertising_Data, ogf=0x08, ocf=0x0037
# )

# # Bind Parameters command to Opcode 0x2041
# bind_layers(
#     HCI_Command_Hdr, HCI_Cmd_LE_Set_Extended_Scan_Parameters, ogf=0x08, ocf=0x0041
# )

# # Bind Enable command to Opcode 0x2042
# bind_layers(HCI_Command_Hdr, HCI_Cmd_LE_Set_Extended_Scan_Enable, ogf=0x08, ocf=0x0042)

# bind_layers(HCI_Command_Hdr, HCI_Cmd_LE_Set_Event_Mask, ogf=0x08, ocf=0x0001)

bind_layers(HCI_Command_Hdr, HCI_Cmd_LE_Set_Public_Address, ogf=0x08, ocf=0x0004)
bind_layers(HCI_Command_Hdr, HCI_Cmd_LE_Custom_Command, ogf=0x08, ocf=0x009E)
# bind_layers(SM_Hdr, SM_Security_Request, sm_command=0x0B)


def l2cap_send(sock: BluetoothSocket, handle: int, cmd, cid: int):
    pkt = HCI_Hdr() / HCI_ACL_Hdr(handle=handle) / L2CAP_Hdr(cid=cid) / cmd
    sock.send(pkt)


def acl_send(sock: BluetoothSocket, handle: int, cmd: L2CAP_Hdr):
    sock.send(HCI_Hdr() / HCI_ACL_Hdr(handle=handle) / cmd)


def sm_send(sock: BluetoothSocket, handle: int, pkt):
    l2cap_send(cmd=SM_Hdr() / pkt, cid=BLE_L2CAP_CID_SM)


# def l2cap_fragment_reassemble(
#     frag_buf: bytes, frag_tot_size: int, pkt: Packet
# ) -> Tuple[bytes, int, Packet]:
#     if pkt.type != 2 or not L2CAP_Hdr in pkt:
#         return b"", 0, pkt

#     if pkt.PB == 2 and pkt[L2CAP_Hdr].len > pkt[HCI_ACL_Hdr].len:
#         return raw(pkt), pkt[L2CAP_Hdr].len, None

#     if pkt.PB == 1 and len(frag_buf) > 0:
#         prev = HCI_Hdr(frag_buf)
#         frag_buf += raw(pkt[HCI_ACL_Hdr:][1:])  # Maybe this can be done differently
#         if (
#             len(raw(prev[L2CAP_Hdr:][1:])) + len(raw(pkt[HCI_ACL_Hdr:][1:]))
#             == frag_tot_size
#         ):
#             return b"", 0, HCI_Hdr(frag_buf)
#         else:
#             return frag_buf, frag_tot_size, None

#     return b"", 0, pkt


def l2cap_fragment_reassemble(
    frag_buf: bytes, frag_tot_size: int, pkt: Packet
) -> Tuple[bytes, int, Packet]:
    # Ignore non-ACL data (Events, Commands)
    if pkt.type != 2:
        return b"", 0, pkt

    # Extract ACL Header Info
    acl_hdr = pkt[HCI_ACL_Hdr]
    pb_flag = acl_hdr.PB

    # Start Fragment (PB=0 or PB=2)
    if pb_flag in [0, 2]:
        if L2CAP_Hdr not in pkt:
            # Should not happen for a valid Start fragment
            return b"", 0, pkt

        l2cap_len = pkt[L2CAP_Hdr].len
        acl_len = acl_hdr.len

        # (ACL Len == L2CAP Len + 4 bytes of L2CAP Header)
        if acl_len >= l2cap_len + 4:
            return b"", 0, pkt

        return raw(pkt), l2cap_len, None

    # Continuing Fragment
    elif pb_flag == 1:
        if not frag_buf:
            # Received a continuation without a start? Drop it.
            return b"", 0, None

        # Append the new payload (raw bytes of ACL payload) to buffer
        prev = HCI_Hdr(frag_buf)
        frag_buf += raw(acl_hdr.payload)

        # Check if complete
        if len(raw(prev[L2CAP_Hdr:][1:])) + len(raw(acl_hdr.payload)) == frag_tot_size:
            return b"", 0, HCI_Hdr(frag_buf)

        # Still not complete
        return frag_buf, frag_tot_size, None

    # Unknown PB flag
    return b"", 0, pkt


def decode_authreq(auth_value):
    bond = (auth_value & 0b00001) >> 0
    mitm = (auth_value & 0b00100) >> 2
    sc = (auth_value & 0b01000) >> 3
    keypress = (auth_value & 0b10000) >> 4
    return bond, mitm, sc, keypress


def find_device_by_name(name: str, pkt) -> bool:
    if len(pkt.data) > 0:
        for hdr in pkt.data:
            if EIR_CompleteLocalName in hdr or EIR_ShortenedLocalName in hdr:
                return hdr.local_name.decode() == name
    return False


def dev_down(id):
    sock = socket.socket(socket.AF_BLUETOOTH, socket.SOCK_RAW, socket.BTPROTO_HCI)
    fcntl.ioctl(sock.fileno(), 0x400448CA, id)  # HCIDEVDOWN
    sock.close()


def dev_up(id):
    sock = socket.socket(socket.AF_BLUETOOTH, socket.SOCK_RAW, socket.BTPROTO_HCI)
    fcntl.ioctl(sock.fileno(), 0x400448C9, id)  # HCIDEVUP
    sock.close()


def get_socket(id):
    try:
        return BluetoothSocket(id)
    except BluetoothSocketError:
        if os.getuid() != 0:
            sys.exit("Please run as root")
        else:
            dev_down(id)
            try:
                return BluetoothSocket(id)
            except BluetoothSocketError as e:
                sys.exit(f"Unable to open socket hci{id}: {e}")


# def att_send(self, cmd):
#     self.l2cap_send(cmd=ATT_Hdr() / cmd, cid=BLE_L2CAP_CID_ATT)
