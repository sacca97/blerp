# from whad.ble.stack.gatt import GattServer, GattClientServer
# from whad.ble.stack.att import ATTLayer

# from whad.ble.profile.attribute import UUID
# from whad.ble.profile import (
#     PrimaryService,
#     Characteristic,
#     GenericProfile,
#     ReadAccess,
#     WriteAccess,
#     Authentication,
#     Encryption,
#     Authorization,
#     ReportReferenceDescriptor,
# )
# from struct import pack, unpack
# from whad.common.converters.hid import HIDConverter
# import sys


# # Define the HID over GATT profile
# class HIDOverGATT(GenericProfile):
#     # Device Information: PnP ID (mandatory in HOGP)
#     service4 = PrimaryService(
#         uuid=UUID(0x180A),
#         level=Characteristic(
#             uuid=UUID(0x2A50),
#             permissions=["read"],
#             value=bytes([0x02, 0x6D, 0x04, 0x23, 0xB0, 0x13, 0x00]),
#             security=ReadAccess(Encryption | Authentication),
#         ),
#     )
#     # Generic access
#     service1 = PrimaryService(
#         uuid=UUID(0x180A),
#         device_name=Characteristic(
#             uuid=UUID.from_name("Device Name"),
#             permissions=["read", "write"],
#             value=bytes("MX Master 3", "utf-8"),
#         ),
#         manufacturer_name=Characteristic(
#             uuid=UUID.from_name("Manufacturer Name String"),
#             permissions=["read", "write"],
#             value=bytes("Logitech", "utf-8"),
#         ),
#         pnp_id=Characteristic(
#             uuid=UUID.from_name("PnP ID"),
#             permissions=["read", "write"],
#             value=bytes.fromhex("026d0423b01300"),
#             security=ReadAccess(Encryption | Authentication),
#         ),
#     )

#     # Battery Level
#     service2 = PrimaryService(
#         uuid=UUID(0x180F),
#         level=Characteristic(
#             uuid=UUID(0x2A19),
#             permissions=["read"],
#             notify=True,
#             indicate=True,
#             value=pack("B", 100),
#             security=ReadAccess(Encryption | Authentication),
#         ),
#     )

#     service3 = PrimaryService(
#         uuid=UUID(0x1812),  # 0x1812
#         report=Characteristic(
#             uuid=UUID(0x2A4D),  # 0x2A4D
#             permissions=["read", "write"],
#             notify=True,
#             indicate=True,
#             value=bytes.fromhex("0000000000000000"),
#             security=ReadAccess(Encryption | Authentication),
#             report_reference_descriptor=ReportReferenceDescriptor(
#                 permissions=["read", "write", "notify"]
#             ),
#         ),
#         report_map=Characteristic(
#             uuid=UUID.from_name("Report Map"),
#             permissions=["read"],
#             value=bytes.fromhex(
#                 "05010902A10185010901A1000509190129031500250175019503810275059501810105010930093109381581257F750895038106C0C0"
#             ),
#             security=ReadAccess(Encryption | Authentication),
#         ),
#         hid_information=Characteristic(
#             uuid=UUID.from_name("HID Information"),
#             permissions=["read"],
#             value=bytes.fromhex("00010002"),
#             security=ReadAccess(Encryption | Authentication),
#         ),
#         hid_control_point=Characteristic(
#             uuid=UUID.from_name("HID Control Point"),
#             permissions=["write_without_response"],
#             value=bytes.fromhex("00"),
#             security=ReadAccess(Encryption | Authentication),
#         ),
#         protocol_mode=Characteristic(
#             uuid=UUID.from_name("Protocol Mode"),
#             permissions=["write_without_response", "read"],
#             notify=True,
#             indicate=True,
#             value=bytes.fromhex("01"),
#         ),
#     )
