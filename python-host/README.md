# pyble

## Requirements

- Python 3.12

## Usage

To run the BLERP MitM attack you must have two modified NimBLE controller attached to you Linux machine and execute the `mitm.py` file.
You have to insert the MAC address of the target Central and the name of the target Peripheral. The two devices must be disconnected when the attack starts.

Since accessing the HCI devices requires root permission by default, you can either change those permission, or setup a Python virtual environment with the requirements in `requirements.txt` and run the `mitm.py` file as root.