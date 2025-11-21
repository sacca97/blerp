import datetime
import logging
from typing import Optional, Tuple

import crypto
import hci as HCI
from constants import *
from helpers import *
from scapy.layers.bluetooth import *


class SecurityManager:
    ea: bytes
    eb: bytes
    ltk: bytes
    preq: bytes
    pres: bytes
    tk: bytes

    def __init__(self, role):
        self.mitm = 0
        self.sc = 0
        self.bond = 1
        self.keypress = 0
        self.ct2 = 1
        self.ltk_size = 16
        self.ecc_key: Optional[crypto.EccKey] = crypto.EccKey.generate()
        self.peer_random_value: Optional[bytes] = None
        self.peer_public_key_x: bytes = bytes(32)
        self.peer_public_key_y = bytes(32)
        self.role = role
        self.r: bytes = None
        self.dhkey = None
        self.ltk = None
        self.confirm_value = 0
        self.stk = None
        self.complete = False

        self.ia = bytes(6)  # Initiator address
        self.ra = bytes(6)  # Responder address
        self.iat = 0  # Initiator address type
        self.rat = 0  # Responder address type

    @property
    def authreq(self):
        return self.bond << 0 | self.mitm << 2 | self.sc << 3 | self.keypress << 4

    @property
    def pkx(self) -> Tuple[bytes, bytes]:
        return (self.ecc_key.x[::-1], self.peer_public_key_x)

    @property
    def pka(self) -> bytes:
        return self.pkx[0 if self.role == BLE_ROLE_CENTRAL else 1]

    @property
    def pkb(self) -> bytes:
        return self.pkx[0 if self.role == BLE_ROLE_PERIPHERAL else 1]

    @property
    def nx(self) -> Tuple[bytes, bytes]:
        assert self.peer_random_value
        return (self.r, self.peer_random_value)

    @property
    def na(self) -> bytes:
        return self.nx[0 if self.role == BLE_ROLE_CENTRAL else 1]

    @property
    def nb(self) -> bytes:
        return self.nx[0 if self.role == BLE_ROLE_PERIPHERAL else 1]

    def send(self, sock: BluetoothUserSocket, handle: int, pkt: Packet):
        l2cap_send(sock, handle, cmd=SM_Hdr() / pkt, cid=BLE_L2CAP_CID_SM)

    def pair(self, sock: BluetoothUserSocket, handle: int):
        fake_authreq_temp = self.bond << 0 | 1 << 2 | 1 << 3 | self.keypress << 4
        if self.role == BLE_ROLE_CENTRAL:
            # self.start_time = datetime.datetime.now()
            # logging.info("Starting pairing")
            pkt = SM_Pairing_Request(
                authentication=fake_authreq_temp,
                initiator_key_distribution=0x01,
                responder_key_distribution=0x01,
            )
            self.preq = SM_Hdr(sm_command=0x01) / pkt
            self.send(sock, handle, pkt)
            print(f"Pairing request: {self.preq.summary()}")
        else:
            self.send(
                sock, handle, SM_Security_Request(authentication=fake_authreq_temp)
            )

    def set_own_address(self, addr: str, address_type: int):
        addr = addr.replace(":", "")
        if self.role == BLE_ROLE_CENTRAL:
            self.ia = bytes.fromhex(addr)
            self.iat = address_type
        else:
            self.ra = bytes.fromhex(addr)
            self.rat = address_type

    def set_peer_address(self, addr: str, address_type: int):
        addr = addr.replace(":", "")

        if self.role == BLE_ROLE_CENTRAL:
            self.ra = bytes.fromhex(addr)
            self.rat = address_type
        else:
            self.ia = bytes.fromhex(addr)
            self.iat = address_type

    def on_message_rx(self, sock: BluetoothUserSocket, handle: int, pkt: Packet):
        if SM_Pairing_Request in pkt:
            logging.info("Received Pairing Request")
            self.on_pairing_request(sock, handle, pkt)
        elif SM_Pairing_Response in pkt:
            logging.info("Received Pairing Response")
            self.on_pairing_response(sock, handle, pkt)
        elif SM_Public_Key in pkt:
            logging.debug("Received Public Key")
            self.on_public_key(sock, handle, pkt)
        elif SM_Confirm in pkt:
            logging.info("Received Confirm")
            self.on_pairing_confirm(sock, handle, pkt)
        elif SM_Random in pkt:
            logging.info("Received Random")
            self.on_pairing_random(sock, handle, pkt)
        elif SM_DHKey_Check in pkt:
            logging.debug("Received DHKey Check")
            self.on_dhkey_check(sock, handle, pkt)
        elif SM_Encryption_Information in pkt:
            logging.debug("Received Encryption Information")
            logging.debug(f"LTK: {pkt.ltk.hex()}")
        else:
            logging.debug(f"Unknown packet {pkt.summary()}")

    def on_pairing_request(
        self, sock: BluetoothUserSocket, handle: int, pkt: Packet = None
    ):
        if self.role == BLE_ROLE_PERIPHERAL:
            self.preq = pkt.getlayer(SM_Hdr)
            pair_rsp = SM_Pairing_Response(
                authentication=self.authreq,
                initiator_key_distribution=0x01,
                responder_key_distribution=0x01,
            )
            self.pres = SM_Hdr(sm_command=0x02) / pair_rsp
            self.send(sock, handle, pair_rsp)

    def on_pairing_response(self, sock: BluetoothUserSocket, handle: int, pkt: Packet):
        if self.role != BLE_ROLE_CENTRAL:
            return

        self.pres = pkt.getlayer(SM_Hdr)

        if self.sc:
            rsp = SM_Public_Key(key_x=self.ecc_key.x[::-1], key_y=self.ecc_key.y[::-1])
        else:
            rsp = self.make_pairing_confirm()
            # logging.info("Sending pairing confirm")

        self.send(
            sock,
            handle,
            rsp,
        )

    def on_public_key(self, sock: BluetoothUserSocket, handle: int, pkt: Packet):
        self.peer_public_key_x = pkt.key_x
        self.peer_public_key_y = pkt.key_y

        self.dhkey = self.ecc_key.dh(pkt.key_x[::-1], pkt.key_y[::-1])[::-1]
        if self.role == BLE_ROLE_PERIPHERAL:
            # Need to compute DHKey
            self.send(
                sock,
                handle,
                SM_Public_Key(key_x=self.ecc_key.x[::-1], key_y=self.ecc_key.y[::-1]),
            )

            self.send(sock, handle, self.make_pairing_confirm())

    def make_pairing_confirm(self):
        self.r = crypto.r()
        if self.sc:
            z = 0  # JW only for now
            if self.role == BLE_ROLE_CENTRAL:
                confirm_value = crypto.f4(
                    self.pka, self.pkb, self.r, bytes([z])
                )  # pka, pkb, r, z
            else:
                confirm_value = crypto.f4(
                    self.pkb, self.pka, self.r, bytes([z])
                )  # pkb, pka, r, z
        else:
            self.tk = bytes(16)
            logging.debug(f"TK: {self.tk.hex()}")
            logging.debug(f"r: {self.r.hex()}")
            logging.debug(f"Preq: {bytes(self.preq).hex()}")
            logging.debug(f"Pres: {bytes(self.pres).hex()}")
            logging.debug(f"iat: {self.iat}")
            logging.debug(f"rat: {self.rat}")
            logging.debug(f"ia: {self.ia.hex()}")
            logging.debug(f"ra: {self.ra.hex()}")

            confirm_value = crypto.c1(
                self.tk,
                self.r,
                self.preq,
                self.pres,
                self.iat,
                self.rat,
                self.ia[::-1],
                self.ra[::-1],
            )
        return SM_Confirm(confirm=confirm_value)

    def on_pairing_confirm(self, sock: BluetoothUserSocket, handle: int, pkt: Packet):
        self.confirm_value = pkt.confirm

        if self.sc:
            if self.role == BLE_ROLE_CENTRAL:
                assert self.r is not None
                self.send(sock, handle, SM_Random(random=self.r))
        else:
            if self.role == BLE_ROLE_CENTRAL:
                assert self.r is not None
                self.send(sock, handle, SM_Random(random=self.r))
                # logging.info("Sending pairing random")
            else:
                self.send(
                    sock,
                    handle,
                    self.make_pairing_confirm(),
                )

    # def make_pairing_random(self):
    #     return SM_Random(random=self.r)

    def on_pairing_random_legacy(self, sock, handle, pkt):
        logging.debug(f"TK: {self.tk.hex()}")
        logging.debug(f"r: {self.r.hex()}")
        logging.debug(f"Preq: {bytes(self.preq).hex()}")
        logging.debug(f"Pres: {bytes(self.pres).hex()}")
        logging.debug(f"iat: {self.iat}")
        logging.debug(f"rat: {self.rat}")
        logging.debug(f"ia: {self.ia.hex()}")
        logging.debug(f"ra: {self.ra.hex()}")

        confirm_verify = crypto.c1(
            self.tk,
            pkt.random,
            self.preq,
            self.pres,
            self.iat,
            self.rat,
            self.ia[::-1],
            self.ra[::-1],
        )

        logging.debug(f"Confirm verify: {confirm_verify.hex()}")
        logging.debug(f"Confirm value: {self.confirm_value.hex()}")

        if confirm_verify != self.confirm_value:
            # logging.info("Legacy pairing confirm failed")
            self.send(sock, handle, SM_Failed(reason=0x04))
            return

        if self.role == BLE_ROLE_CENTRAL:
            mrand = self.r
            srand = pkt.random
        else:
            mrand = pkt.random
            srand = self.r

        self.stk = crypto.s1(self.tk, srand, mrand)

        self.ltk = crypto.r()
        # logging.info(f"LTK: {self.ltk.hex()}")

        if self.role == BLE_ROLE_CENTRAL:
            HCI.send_cmd(
                sock,
                HCI_Cmd_LE_Enable_Encryption(
                    handle=handle,
                    ltk=self.stk,
                ),
            )
            # HCI.wait_event(sock, HCI_Event_Encryption_Change)
            # logging.info("Encryption enabled")

        else:
            self.send(sock, handle, SM_Random(random=self.r))
            # logging.info("Sending pairing random")
            # cmd = HCI.wait_event(sock, HCI_LE_Meta_Long_Term_Key_Request)
            # # logging.info(f"Received LTK request {cmd}")
            # assert self.ltk is not None
            # HCI.send_cmd(
            #     sock,
            #     HCI_Cmd_LE_Long_Term_Key_Request_Reply(handle=cmd.handle, ltk=self.stk),
            # )
            # HCI.wait_event(sock, HCI_Event_Encryption_Change)
            # self.send(sock, handle, SM_Encryption_Information(ltk=self.ltk))
            # logging.info("Peripheral pairing complete")

    def distribute_keys(self, sock: BluetoothUserSocket, handle: int):
        if self.role == BLE_ROLE_PERIPHERAL:
            if self.sc:
                pass
            else:
                # logging.info("Distributing keys legacy")
                self.send(sock, handle, SM_Encryption_Information(ltk=self.ltk))
                self.send(
                    sock,
                    handle,
                    SM_Master_Identification(ediv=24315, rand=crypto.r()[:8]),
                )  # todo: FIXME
                # self.send(sock, handle, SM_Identity_Information(irk=self.stk))
                self.send(
                    sock, handle, SM_Identity_Address_Information(address=self.ia)
                )

    def on_pairing_random(self, sock: BluetoothUserSocket, handle: int, pkt: Packet):
        if not self.sc:
            # logging.info("Legacy pairing random")
            return self.on_pairing_random_legacy(sock, handle, pkt)

        self.peer_random_value = pkt.random
        if self.role == BLE_ROLE_CENTRAL:
            confirm_verify = crypto.f4(
                self.pkb, self.pka, pkt.random, bytes([0])
            )  # Valid for JW and NUMCMP
            if confirm_verify != self.confirm_value:
                self.send(sock, handle, SM_Failed(reason=0x04))

        a = self.ia[::-1] + bytes([self.iat])
        b = self.ra[::-1] + bytes([self.rat])

        (mac_key, self.ltk) = crypto.f5(self.dhkey, self.na, self.nb, a, b)

        # Only JW and NUMCMP
        ra = bytes(16)
        rb = ra

        assert self.preq and self.pres
        io_cap_a = bytes(
            [
                self.preq.iocap,
                self.preq.oob,
                self.preq.authentication,
            ]
        )
        io_cap_b = bytes(
            [
                self.pres.iocap,
                self.pres.oob,
                self.pres.authentication,
            ]
        )

        self.ea = crypto.f6(mac_key, self.na, self.nb, rb, io_cap_a, a, b)
        self.eb = crypto.f6(mac_key, self.nb, self.na, ra, io_cap_b, b, a)

        if self.role == BLE_ROLE_CENTRAL:
            self.send(sock, handle, SM_DHKey_Check(dhkey_check=self.ea))
        else:
            self.send(sock, handle, SM_Random(random=self.r))

    def on_dhkey_check(self, sock: BluetoothUserSocket, handle: int, pkt: Packet):
        expected = self.eb if self.role == BLE_ROLE_CENTRAL else self.ea

        if pkt.dhkey_check != expected:
            logging.warning("DHKey Check failed")
            self.send(sock, handle, SM_Failed(reason=11))

        if self.role == BLE_ROLE_CENTRAL:
            # Central starts encryption
            HCI.send_cmd(
                sock,
                HCI_Cmd_LE_Enable_Encryption(
                    handle=handle,
                    ltk=self.ltk,
                ),
            )
            # print(f"Pairing done in {(datetime.datetime.now() - self.start_time)}")
        else:
            # Peripheral sends dhkey check and waits for controller to ask for LTK
            self.send(sock, handle, SM_DHKey_Check(dhkey_check=self.eb))
            cmd = HCI.wait_event(sock, HCI_LE_Meta_Long_Term_Key_Request)
            assert self.ltk is not None
            HCI.send_cmd(
                sock,
                HCI_Cmd_LE_Long_Term_Key_Request_Reply(handle=cmd.handle, ltk=self.ltk),
            )
            # logging.info("Pairing complete")
