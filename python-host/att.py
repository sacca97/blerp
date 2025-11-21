from typing import Optional, Tuple

from constants import *
from helpers import l2cap_send
from scapy.layers.bluetooth import *


class ATTManager:
    def __init__(self):
        self.mtu = 23
        self.msgs = [
            b"\x01\x00\x09\x00\x00\x18\x0a\x00\x0d\x00\x01\x18\x0e\x00\x1c\x00\x0a\x18",
            b"\x1d\x00\x20\x00\x0f\x18\x21\x00\x40\x00\x12\x18",
            b"\x41\x00\xff\xff\x6d\x04\x00\x20\x1f\x01\x00\x80\x00\x10\x00\x00\x00\x00\x01\x00",
        ]

    def send(self, sock: BluetoothUserSocket, handle: int, pkt: Packet):
        l2cap_send(sock, handle, cmd=ATT_Hdr() / pkt, cid=BLE_L2CAP_CID_ATT)

    # def do_gatt_read(self, sock: BluetoothUserSocket, handle: int, uuid: int):
    #     self.send(sock, handle, ATT_Read_Request(uuid=uuid))
    #     pass

    # def do_gatt_write(self, sock: BluetoothUserSocket, handle: int, data: bytes):
    #     self.send(sock, handle, ATT_Write_Request(data=data))
    #     pass

    def on_message_rx(self, sock: BluetoothUserSocket, handle: int, pkt: Packet):
        if ATT_Exchange_MTU_Request in pkt:
            self.send(sock, handle, ATT_Exchange_MTU_Response(mtu=self.mtu))
        elif ATT_Read_By_Group_Type_Request in pkt:
            self.send(sock, handle, ATT_Read_By_Group_Type_Response())
        elif ATT_Read_By_Type_Request in pkt:
            self.send(sock, handle, ATT_Read_By_Type_Response())
        elif ATT_Read_Request in pkt:
            self.send(sock, handle, ATT_Read_Response())
        elif ATT_Find_By_Type_Value_Request in pkt:
            self.send(sock, handle, ATT_Find_By_Type_Value_Response())
        # if pkt.getlayer(ATT_Read_By_Group_Type_Request):
        #     msg = self.msgs.pop(0)
        #     rsp = ATT_Read_By_Group_Type_Response(
        #         length=len(msg),
        #         data=msg,
        #     )
        #     return rsp
        # elif pkt.getlayer(ATT_Read_By_Type_Request):
        #     match int(pkt.uuid):
        #         case int(0x2803):  # GATT Characteristic Declaration
        #             # TODO: handle different handles
        #             pass
        #         case int(0x2A50):  # GATT PnP ID
        #             rsp = ATT_Read_By_Type_Response(
        #                 len=9, handles=b"\x1C\x00\x02\x6D\x04\x23\xB0\x13\x00"
        #             )
        #         case _:
        #             pass
        # elif pkt.getlayer(ATT_Read_Request):
        #     match int(pkt.gatt_handle):
        #         case int(0x0023):  # GATT HID Information
        #             # TODO: Requires authentication/encryption
        #             rsp = ATT_Error_Response(request=0x000A, handle=0x0023, ecode=0x05)
        #         case _:
        #             pass

        # print(pkt)
