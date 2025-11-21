import asyncio
import platform
import sys

from bleak import BleakClient, BleakScanner

address = "F73F3A5F-F926-33B4-CC00-A28B397D3BB0"

OS_NAME = platform.system()
print(f"OS: {OS_NAME}")


async def scan():
    devices = await BleakScanner.discover()

    for d in devices:
        print(d)


async def pair(address):
    client = BleakClient(address)
    await client.connect()
    print("Connected!")
    if OS_NAME != "Darwin":
        await client.pair()
        print("Paired!")
    else:
        # macOS reads protected charateristic to start security
        await client.read_gatt_char("00010001-0000-1000-8000-011f2000046d")

    val = input("1) Disconnect\n2) Unpair\nSelect action: ")
    if val == "1":
        await client.disconnect()
        print("Disconnected!")
    elif val == "2":
        await client.unpair()
        print("Unpaired!")


async def unpair(address):
    client = BleakClient(address)
    await client.connect()
    await client.unpair()
    print("Unpaired!")


if __name__ == "__main__":
    args = sys.argv[1]
    if args == "pair":
        asyncio.run(pair(address))
    elif args == "unpair":
        asyncio.run(unpair(address))
    elif args == "scan":
        asyncio.run(scan())
    else:
        print("Unknown command.")
