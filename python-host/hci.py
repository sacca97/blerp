import logging
from typing import final

from scapy.layers.bluetooth import *
from scapy.layers.bluetooth4LE import *


def send_cmd(sock: BluetoothUserSocket, cmd: Packet):
    pkt = HCI_Hdr() / HCI_Command_Hdr() / cmd
    # opcode = pkt.opcode

    sock.send(pkt)
    while True:
        r = sock.recv()
        if r.type == 0x04 and r.code in (0xE, 0x0F):  # and r.opcode == opcode:
            if r.status != 0:
                logging.warning(f"Command failed {cmd}")
                return False
            return r


# def on_message_rx(dev: Device, sock: BluetoothUserSocket, cmd: Packet):
#     if cmd is None:
#         return False

#     if HCI_LE_Meta_Long_Term_Key_Request in cmd:
#         assert dev.ltk is not None or dev.stk is not None
#         send_cmd(sock, HCI_Cmd_LE_Long_Term_Key_Request_Reply(handle=cmd.handle, ltk=dev.sm.stk))
#         # logging.info(f"Long Term Key Request")
#         return False

#     if HCI_Event_Encryption_Change in cmd:
#         # logging.info(f"Encryption {'enabled' if cmd.enabled else 'disabled'}")
#         return True

#     if HCI_Event_Number_Of_Completed_Packets in cmd:
#         return False

#     return False


def wait_event(sock: BluetoothUserSocket, evt: Packet):
    status = 0
    while True:
        pkt = sock.recv()
        if HCI_Event_Hdr in pkt and evt in pkt:

            try:
                status = pkt.status
            except:
                status = 0
            finally:
                if status == 0:
                    return pkt
                else:
                    return None
