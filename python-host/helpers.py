import fcntl
import logging
import os
import sys
from typing import Tuple

from constants import *
from scapy.fields import *
from scapy.layers.bluetooth import *
from scapy.packet import *


def hci_cmd_get(cmd):
    return HCI_Hdr() / HCI_Command_Hdr() / cmd


class HCI_Cmd_LE_Set_Public_Address(Packet):
    name = "LE Set Public Address"
    fields_desc = [LEMACField("address", None)]


class HCI_Cmd_LE_Custom_Command(Packet):
    name = "LE Custom Command"
    fields_desc = [LEShortField("opcode", 0)]


class SM_Security_Request(Packet):
    name = "Security Request"
    fields_desc = [BitField("authentication", 0, 8)]


bind_layers(HCI_Command_Hdr, HCI_Cmd_LE_Set_Public_Address, ogf=0x08, ocf=0x2004)
bind_layers(HCI_Command_Hdr, HCI_Cmd_LE_Custom_Command, ogf=0x08, ocf=0x209E)
bind_layers(SM_Hdr, SM_Security_Request, sm_command=0x0B)


def l2cap_send(sock: BluetoothUserSocket, handle: int, cmd, cid: int):
    pkt = HCI_Hdr() / HCI_ACL_Hdr(handle=handle) / L2CAP_Hdr(cid=cid) / cmd
    sock.send(pkt)


def acl_send(sock: BluetoothUserSocket, handle: int, cmd: L2CAP_Hdr):
    sock.send(HCI_Hdr() / HCI_ACL_Hdr(handle=handle) / cmd)


def sm_send(sock: BluetoothUserSocket, handle: int, pkt):
    l2cap_send(cmd=SM_Hdr() / pkt, cid=BLE_L2CAP_CID_SM)


def l2cap_fragment_reassemble(
    frag_buf: bytes, frag_tot_size: int, pkt: Packet
) -> Tuple[bytes, int, Packet]:
    if pkt.type != 2 or not L2CAP_Hdr in pkt:
        return b"", 0, pkt

    if pkt.PB == 2 and pkt[L2CAP_Hdr].len > pkt[HCI_ACL_Hdr].len:
        return raw(pkt), pkt[L2CAP_Hdr].len, None

    if pkt.PB == 1 and len(frag_buf) > 0:
        prev = HCI_Hdr(frag_buf)
        frag_buf += raw(pkt[HCI_ACL_Hdr:][1:])  # Maybe this can be done differently
        if (
            len(raw(prev[L2CAP_Hdr:][1:])) + len(raw(pkt[HCI_ACL_Hdr:][1:]))
            == frag_tot_size
        ):
            return b"", 0, HCI_Hdr(frag_buf)
        else:
            return frag_buf, frag_tot_size, None

    return b"", 0, pkt


def find_device_by_name(name: str, pkt: HCI_LE_Meta_Advertising_Report) -> str:
    if pkt.len > 0:
        for hdr in pkt.data:
            if EIR_CompleteLocalName in hdr:
                logging.debug(
                    f"Found device {hdr.local_name.decode()} address {pkt.addr}"
                )
                if hdr.local_name.decode() == name:
                    return pkt.addr, pkt.atype
    return None, None


def dev_down(id=1):
    sock = socket.socket(socket.AF_BLUETOOTH, socket.SOCK_RAW, socket.BTPROTO_HCI)
    sock.bind((id,))
    fcntl.ioctl(sock.fileno(), HCI_DEV_DOWN, id)
    sock.close()


def get_socket(id):
    try:
        return BluetoothUserSocket(id)
    except BluetoothSocketError as e:
        if os.getuid() != 0:
            sys.exit("Please run as root")
        else:
            dev_down(id)
            try:
                return BluetoothUserSocket(id)
            except BluetoothSocketError as e:
                sys.exit(f"Unable to open socket hci{id}: {e}")


# def att_send(self, cmd):
#     self.l2cap_send(cmd=ATT_Hdr() / cmd, cid=BLE_L2CAP_CID_ATT)
