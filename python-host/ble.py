#!./pyble/bin python
import asyncio
import datetime
import fcntl
import logging
import signal
import socket
import sys
from operator import add

import hci as HCI
from att import ATTManager
from constants import *
from helpers import *
from scapy.compat import raw
from scapy.layers.bluetooth import *
from scapy.layers.bluetooth4LE import *
from smp import SecurityManager

# Scapy does not support enhanced connection complete event
# bind_layers(HCI_Event_LE_Meta, HCI_LE_Meta_Enhanced_Connection_Complete, event=10)
# Custom HCI command, we want to set the public address at runtime
# bind_layers(HCI_Command_Hdr, HCI_Cmd_LE_Set_Public_Address, opcode=0x2004)

# bind_layers(HCI_Command_Hdr, HCI_Cmd_LE_Custom_Command, opcode=0x209E)

logging.basicConfig(
    format="[%(asctime)s] %(message)s", datefmt="%H:%M:%S", level=logging.INFO
)


class Device:
    pairing_task = None

    def __init__(
        self,
        id: int,
        role: int,
        addr: str,
        addr_type: int,
    ):
        self.id = id
        self.role = role
        self.handle = None
        self.sm = SecurityManager(role)
        self.att = ATTManager()
        self.forwarding = False
        self.sock = None
        self.mtu = 23  # TODO update this dinamically
        self.addr = addr
        self.addr_type = addr_type
        self.start_time = 0
        self.encrypted = False
        self.forwarded_packets = 0
        self.initialized = False

    @property
    def own_address(self):
        return bytes(self.addr.replace(":", ""), "utf-8")

    def set_role(self, role):
        self.role = role

    def initialize(self):
        self.sock = get_socket(self.id)

        HCI.send_cmd(self.sock, HCI_Cmd_Reset())

        HCI.send_cmd(self.sock, HCI_Cmd_Set_Event_Mask())

        self.set_address(self.addr, self.addr_type)

        self.initialized = True

    def set_peripheral_mode(self, addr=None, addr_type=None, adv_data=None):
        if not self.initialized:
            self.initialize()

        # if addr is None:
        #     self.copy_advertising_data(target_name=name)
        #     self.set_address(self.addr, self.addr_type)
        #     # self.set_advertising_data()
        # else:
        self.set_address(addr, addr_type)
        self.copy_adv_dat_from_raw(addr, addr_type, adv_data)

        # else:
        #     self.set_address(addr, addr_type)
        #     self.set_advertising_data(appearance=appearance, name=name)

        HCI.send_cmd(self.sock, HCI_Cmd_LE_Custom_Command(opcode=1))

        # TODO: channel_map settings?
        HCI.send_cmd(
            self.sock, HCI_Cmd_LE_Set_Advertising_Parameters(oatype=self.addr_type)
        )
        self.stop_advertising()
        self.start_advertising()

    def start_advertising(self):
        if self.role == BLE_ROLE_PERIPHERAL:
            HCI.send_cmd(self.sock, HCI_Cmd_LE_Set_Advertise_Enable(enable=1))
            logging.info("Peripheral: Advertising started")
            pkt = HCI.wait_event(self.sock, HCI_LE_Meta_Connection_Complete)
            if pkt is not None:
                self.handle = pkt.handle
                self.sm.set_peer_address(pkt.paddr, pkt.patype)

                logging.info("Peripheral: Connection complete")
                # tmp = L2CAP_Connection_Parameter_Update_Request(min_interval=20, max_interval=36, slave_latency=4, timeout_mult=90)
                # l2cap_send(self.sock, self.handle, tmp, 5)
                # print("Sent L2CAP_Connection_Parameter_Update_Request")
            # Send a L2CAP connection parameter update request
            else:
                logging.warning("Connection failed")

    def stop_advertising(self):
        HCI.send_cmd(self.sock, HCI_Cmd_LE_Set_Advertise_Enable(enable=0))

    def copy_advertising_data(self, target_name: str = None):
        addr, addr_type, adv_data = self.start_targeted_scan(
            bname=target_name, get_data=True
        )
        if addr is not None and adv_data is not None:
            # Set address
            self.addr = addr
            self.addr_type = addr_type
            # logging.info(f"Address copied from {addr}")

            # Set advertising data
            HCI.send_cmd(self.sock, HCI_Cmd_LE_Set_Advertising_Data(data=adv_data))
            # logging.info(f"Advertising data copied")

    def copy_adv_dat_from_raw(self, addr, addr_type, raw_data: list):
        # Set address
        self.addr = addr
        self.addr_type = addr_type
        # logging.info(f"Address copied from {addr}")

        HCI.send_cmd(self.sock, HCI_Cmd_LE_Set_Advertising_Data(data=raw_data))
        logging.info(f"Advertising data copied")

    def set_advertising_data(self, appearance=962, name="G603", service=0x1812):
        adv_data = [
            EIR_Hdr() / EIR_Flags(flags=["general_disc_mode", "br_edr_not_supported"]),
            EIR_Hdr() / EIR_CompleteList16BitServiceUUIDs(svc_uuids=[service]),
            EIR_Hdr() / EIR_CompleteLocalName(local_name=name),
            EIR_Hdr(type="appearance")
            / EIR_Raw(data=appearance.to_bytes(2, byteorder="little")),
        ]

        HCI.send_cmd(self.sock, HCI_Cmd_LE_Set_Advertising_Data(data=adv_data))
        # HCI.send_cmd(self.sock,HCI_Cmd_LE_Set_Advertising_Data(data=adv_data))

    def set_advertising_parameters(self):
        if self.role == BLE_ROLE_PERIPHERAL:
            HCI.send_cmd(self.sock, HCI_Cmd_LE_Set_Advertising_Parameters(oatype=1))

    def set_scan_parameters(self, scan_type=1):
        if self.role == BLE_ROLE_CENTRAL:
            return self.sock.sr(
                HCI_Hdr()
                / HCI_Command_Hdr()
                / HCI_Cmd_LE_Set_Scan_Parameters(type=scan_type)
            )

    def start_scanning(self):
        logging.info("Starting scanning")
        HCI.send_cmd(self.sock, HCI_Cmd_LE_Set_Scan_Parameters(type=0))
        HCI.send_cmd(self.sock, HCI_Cmd_LE_Set_Scan_Enable(enable=1, filter_dups=1))
        # self.scanning = True

    def stop_scanning(self):
        HCI.send_cmd(self.sock, HCI_Cmd_LE_Set_Scan_Enable(enable=0))
        # self.scanning = False

    # EIR_Hdr
    def scan_result(self):
        pass

    def start_targeted_scan(
        self, bdaddr: str = None, bname: str = None, get_data: bool = False
    ):
        self.start_scanning()
        dev_list = []
        while True:
            pkt = HCI.wait_event(self.sock, HCI_LE_Meta_Advertising_Report)
            if pkt is not None:
                pkt = pkt[HCI_LE_Meta_Advertising_Report]
                if pkt.addr not in dev_list:
                    dev_list.append(pkt.addr)
                    # logging.info(f"Found new device {pkt.addr}")
            else:
                continue

            if bdaddr is not None:
                if bdaddr.lower() == pkt.addr:
                    self.stop_scanning()
                    logging.info(f"Target acquired: {pkt.addr}")
                    # if pkt.len > 0:
                    # print(pkt.data)
                    # pkt.show()
                    # save scanning data
                    if get_data:
                        return pkt.addr, pkt.atype, pkt.data
                    return pkt.addr, pkt.atype, None
            if bname is not None:
                addr, addr_type = find_device_by_name(bname, pkt)
                if addr is not None:
                    # logging.info(f"Target acquired: {bname} with address: {addr}")

                    self.stop_scanning()
                    # if pkt.len > 0:
                    # print(pkt.data)
                    # pkt.show()
                    # save scanning data
                    if get_data:
                        return addr, addr_type, pkt.data

                    return addr, addr_type, None
        return None, None, None

    def set_address(self, addr, addr_type):
        self.sm.set_own_address(addr, addr_type)
        cmd = (
            HCI_Cmd_LE_Set_Random_Address(address=addr)
            if addr_type == 1
            else HCI_Cmd_LE_Set_Public_Address(address=addr)
        )
        HCI.send_cmd(self.sock, cmd)

    def connect(self, bdaddr, addr_type=1):
        if self.role == BLE_ROLE_CENTRAL:
            HCI.send_cmd(
                self.sock, HCI_Cmd_LE_Create_Connection(patype=addr_type, paddr=bdaddr)
            )
            pkt = HCI.wait_event(
                self.sock, HCI_LE_Meta_Connection_Complete
            )  # We block until we get connection complete

            if pkt is not None:
                self.handle = pkt.handle
                self.sm.set_peer_address(pkt.paddr, pkt.patype)
                logging.info(f"Central: Connection complete")

                # time.sleep(1)
                # if not self.mitm:
                # self.sm.pair(self.sock, self.handle)
            # pair_req = self.sm.pair(bdaddr, addr_type)[0]
            # self.sm_send(pair_req)

    def disconnect(self):
        if HCI.send_cmd(self.sock, HCI_Cmd_Disconnect(handle=self.handle, reason=0x13)):
            HCI.wait_event(self.sock, HCI_Event_Disconnection_Complete)
            logging.info("Disconnected")

    def reset(self):
        return HCI.send_cmd(self.sock, HCI_Cmd_Reset())

    def receive(self, timeout=None) -> HCI_Hdr:
        frag_buffer = b""
        frag_total_size = 0

        while True:
            frag_buffer, frag_total_size, pkt = l2cap_fragment_reassemble(
                frag_buffer, frag_total_size, self.sock.recv()
            )
            if pkt is not None:
                return pkt

    def forward(self, pkt: Packet):
        pkt = pkt.getlayer(L2CAP_Hdr)
        role = "Central" if self.role == BLE_ROLE_CENTRAL else "Peripheral"
        logging.debug(f"Forwarded to {role}: {pkt}")

        acl_send(self.sock, self.handle, pkt)
        # self.forwarded_packets += 1
        # print(f"Forwarded packets to {role}: {self.forwarded_packets}", end="\r")

    def start_pairing(self, block: bool = True):
        if self.role == BLE_ROLE_CENTRAL:
            self.sm.pair(self.sock, self.handle)
            logging.info("Central starting pairing procedure")
        else:
            logging.info("Peripheral starting pairing procedure")
        if not block:
            return

        self.listen()

    def hci_handler(self, pkt: Packet):
        if HCI_LE_Meta_Long_Term_Key_Request in pkt:
            # assert self.sm.ltk is not None
            if self.role == BLE_ROLE_PERIPHERAL:
                # logging.info(f"Long Term Key Request")
                if self.sm.stk is None:
                    HCI.send_cmd(
                        self.sock,
                        HCI_Cmd_LE_Long_Term_Key_Request_Negative_Reply(
                            handle=pkt.handle
                        ),
                    )
                else:
                    HCI.send_cmd(
                        self.sock,
                        HCI_Cmd_LE_Long_Term_Key_Request_Reply(
                            handle=pkt.handle, ltk=self.sm.stk
                        ),
                    )
            # logging.info(f"Long Term Key Request")
        elif HCI_Event_Encryption_Change in pkt:
            if not self.encrypted and pkt.status == 0:
                self.sm.distribute_keys(self.sock, self.handle)
                self.encrypted = True
                logging.info(
                    f"{'Peripheral' if self.role else 'Central'}: encryption enabled"
                )
        elif HCI_LE_Meta_Connection_Update_Complete in pkt:
            if pkt.status == 255 and self.role == BLE_ROLE_PERIPHERAL:
                self.sm.pair(self.sock, self.handle)
                logging.info(f"Peripheral: sent security request")
        elif HCI_Event_Disconnection_Complete in pkt:
            logging.info(f"Disconnected: reason {pkt.reason} error: {pkt.status}")

    def on_message_rx(self, pkt: Packet):
        if pkt is None:
            return None
        # we want to handle the ATT and SM packets locally if forwarding is disabled

        if HCI_ACL_Hdr in pkt:
            if SM_Hdr in pkt:
                self.sm.on_message_rx(self.sock, self.handle, pkt)
            elif ATT_Hdr in pkt and not self.forwarding:
                self.att.on_message_rx(self.sock, self.handle, pkt)
            elif L2CAP_CmdHdr in pkt:
                return None
            else:
                if ATT_Read_Request in pkt:
                    if pkt.gatt_handle == 0x001F:
                        logging.info("Tampering with battery level")
                if ATT_Read_Response in pkt:
                    if pkt.value == b"d":
                        pkt.setfieldval("value", b"E")
                    # print(f"Forwarding packet {pkt}")
                return pkt
        elif HCI_Event_Hdr in pkt:
            self.hci_handler(pkt)

        return None
        #         self.pairing_task.cancel()

    def listen(self):
        while True:
            self.on_message_rx(self.receive())
            if self.encrypted and not self.sm.complete:
                self.sm.complete = True
                logging.info("Pairing completed")
                break

    def __del__(self):
        if self.sock is not None:
            self.disconnect()
            self.sock.flush()
            self.sock.close()


def signal_handler(sig, frame):
    sys.stdout.flush()
    logging.info("Exiting...")
    sys.exit(0)


if __name__ == "__main__":
    signal.signal(signal.SIGINT, signal_handler)
    dev = Device(id=1, role=BLE_ROLE_CENTRAL, addr="50:ED:3C:00:BC:BA", addr_type=0)

    dev.initialize()

    addr, addr_type, data = dev.start_targeted_scan(bname="G603", get_data=True)

    # dev.set_peripheral_mode(addr=addr, addr_type=addr_type, adv_data=data)

    # dev.sm.set_peer_address(target, 0)  # "CA:34:8B:54:7E:52"
    # dev.set_peripheral_mode(addr=addr, addr_type=addr_type, adv_data=data)
    dev.connect(bdaddr=addr, addr_type=addr_type)
    dev.sm.pair(dev.sock, dev.handle)
    dev.listen()
    # input("Press Enter to Connect...")
    # target = dev.start_targeted_scan(bname="G603")
    # dev.connect(bdaddr=addr, addr_type=atype)
    # dev.start_pairing()

    # dev = Device(id=1, role=BLE_ROLE_PERIPHERAL, addr="CA:34:8B:54:7E:52", addr_type=1)
    # dev.set_peripheral_mode()

    input("Press Enter to start scanning...")

    # dev.listen()
