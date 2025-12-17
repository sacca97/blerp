#!/usr/bin/env python3
"""
Example script demonstrating BLE HID keyboard and mouse emulation.

Usage:
    # Keyboard mode
    sudo python3 hid_example.py --profile keyboard --hci 0

    # Mouse mode
    sudo python3 hid_example.py --profile mouse --hci 0
"""

import argparse
import logging
import signal
import sys
import time

from att import HIDProfile
from ble import Device
from constants import *

logging.basicConfig(
    format="[%(asctime)s] %(message)s", datefmt="%H:%M:%S", level=logging.INFO
)


def signal_handler(sig, frame):
    sys.stdout.flush()
    logging.info("Exiting...")
    sys.exit(0)


def wait_for_notifications(dev: Device, timeout: float = 30.0):
    """Wait for central to enable notifications on the report characteristic."""
    if not dev.att.report_handle:
        logging.warning("No report handle defined!")
        return

    logging.info("Waiting for central to enable notifications...")
    start_time = time.time()
    while time.time() - start_time < timeout:
        # Check if notifications are enabled for the report handle
        cccd_value = dev.att.db.cccd_state.get(dev.att.report_handle + 1, 0)
        # Note: In att.py, cccd_handle is technically report_handle + 2 (Report Ref is +1?)
        # Let's check att.py again.
        # CCCD is added AFTER Report Char Value.
        # Decl (N) -> Value (N+1) -> Descriptor (N+2)?
        # Actually, let's just iterate cccd_state and see if ANY is enabled.
        # Or better, check the specific handle if we can find it.
        
        # Simpler approach: check if ANY notification is enabled
        if any(v & 0x01 for v in dev.att.db.cccd_state.values()):
            logging.info("Notifications enabled! Starting demo...")
            return

        # Process incoming packets while waiting
        # We use a non-blocking receive if possible, or just receive one packet
        # scapy's socket is blocking by default.
        # We can use select or just rely on the fact that if we are here, we are connected.
        try:
             dev.on_message_rx(dev.receive())
        except Exception as e:
            logging.error(f"Error while waiting: {e}")
            break
            
    logging.warning("Timeout waiting for notifications. Starting demo anyway...")

def keyboard_demo(dev: Device):
    """Demonstrate keyboard functionality."""
    logging.info("Device encrypted and ready!")
    
    wait_for_notifications(dev)
    
    logging.info("Sending keyboard input...")
    time.sleep(1) # Small delay after enable
    
    # Type some text
    dev.att.send_text("Hello from BLE keyboard!")
    time.sleep(1)

    # Send individual keys
    dev.att.send_key('\n')  # Enter
    time.sleep(0.5)

    dev.att.send_text("Testing special characters: !@#$%")
    time.sleep(1)

    logging.info("Keyboard demo complete. Continuing to listen...")


def mouse_demo(dev: Device):
    """Demonstrate mouse functionality."""
    logging.info("Device encrypted and ready!")
    
    wait_for_notifications(dev)

    logging.info("Sending mouse input...")
    time.sleep(1) # Small delay after enable

    # Move mouse in a square pattern
    logging.info("Moving mouse in square pattern...")
    for _ in range(4):
        dev.att.move_mouse(100, 0)
        time.sleep(0.5)
        dev.att.move_mouse(0, 100)
        time.sleep(0.5)
        dev.att.move_mouse(-100, 0)
        time.sleep(0.5)
        dev.att.move_mouse(0, -100)
        time.sleep(0.5)

    # Click buttons
    logging.info("Left click")
    dev.att.click(button=1)
    time.sleep(1)

    logging.info("Right click")
    dev.att.click(button=2)
    time.sleep(1)

    logging.info("Mouse demo complete. Continuing to listen...")


def main():
    signal.signal(signal.SIGINT, signal_handler)

    parser = argparse.ArgumentParser(description="BLE HID Device Emulator")
    parser.add_argument(
        "--profile",
        choices=["keyboard", "mouse"],
        required=True,
        help="HID profile to emulate",
    )
    parser.add_argument(
        "--hci",
        type=int,
        default=0,
        help="HCI device number (default: 0 for hci0)",
    )
    parser.add_argument(
        "--addr",
        help="Bluetooth address (default: random)",
    )
    parser.add_argument(
        "--addr-type",
        type=int,
        choices=[0, 1],
        default=1,
        help="Address type: 0=public, 1=random (default: 1)",
    )
    parser.add_argument(
        "--demo",
        action="store_true",
        help="Run demo after connection",
    )

    args = parser.parse_args()

    # Map profile string to enum
    profile = HIDProfile.KEYBOARD if args.profile == "keyboard" else HIDProfile.MOUSE

    # Set default address - use different address to force central to treat as new device
    addr = args.addr if args.addr else "C3:22:7B:A4:8D:F9"
    addr_type = args.addr_type

    logging.info(f"Starting BLE HID {args.profile} emulator")
    logging.info(f"Profile: {profile.name}")
    logging.info(f"Address: {addr} (type: {addr_type})")

    with Device(
        id=args.hci,
        role=BLE_ROLE_PERIPHERAL,
        hid_profile=profile
    ) as dev:
        # Initialize device
        dev.initialize(addr, addr_type)

        # Print GATT database for debugging
        dev.att.print_database()

        # Set advertising data (profile-specific)
        dev.set_adv_data()

        # Start advertising
        dev.start_advertising()

        # Custom listen loop with demo support
        logging.info("Device ready. Connect from a BLE central device.")
        if args.demo:
            logging.info("Demo will run automatically after pairing completes")

        demo_run = False
        while True:
            dev.on_message_rx(dev.receive())

            # Check if pairing completed
            if dev.encrypted and not dev.sm.complete:
                dev.sm.complete = True
                logging.info("Pairing completed")

                # Run demo once after encryption
                if args.demo and not demo_run:
                    demo_run = True
                    if profile == HIDProfile.KEYBOARD:
                        keyboard_demo(dev)
                    else:
                        mouse_demo(dev)


if __name__ == "__main__":
    main()
