# BLERP: BLE Re-Pairing Attacks and Defenses

This repository contains everything that was developed for the BLERP paper: the toolkit for the attacks, the fixes, and the ProVerif model.

Everything  is also available at [doi.org/10.5281/zenodo.17671927](https://doi.org/10.5281/zenodo.17671927)

The NDSS 26' paper is available at  

## Requirements

**Hardware:**

  * 2 Nordic nRF52840-DK (PCA10056)

**Software:**

  * Linux
  * [Segger JLink](https://www.segger.com/downloads/jlink/)
  * [Apache newt v1.9.0](https://mynewt.apache.org/latest/newt/install/newt_linux.html)
  * Python 3.12.0 (MitM attack only)
  * A serial device tool (e.g., [tio](https://github.com/tio/tio))

## Toolkit Setup

1.  Clone this repository `git clone github.com/sacca97/blerp.git`
2.  Move into the cloned repository and run `setup.sh`. It will set up the workspace in a subfolder called _blerpae_.
3.  Move into the new folder and run `apply_attacks_patches.sh`. It will patch the NimBLE stack to perform the attacks. 
4.  Modify the `Makefile` by setting the `centralid` variable to your board's 10-digit serial number which can be found on the board itself.
5.  Connect the board to your system via USB and run `make boot-10056 && make central` to build and install the OS and the bleshell application.
6. Connect to the board using the serial tool, e.g., `tio /dev/serial/by-id/your_board_id`. Once connected, press Enter and then Tab to show the list of available commands.


## Testing Peripheral Impersonation

This attack maps to Section IV.B of the paper. The user must pair the target Peripheral with a Central device (e.g., a mouse with a laptop or smartphone). We assume the use of a mouse and an Android device. 

The mouse must be paired with the Android device and turned off (or out of range) during the test. Then the user starts by setting the mouse Bluetooth address in the toolkit with:

The user must first set the spoofed Bluetooth address with:

```sh
set addr=MAC_Address addr_type=random
```

Where `addr` and `addr_type` shall match the ones of the impersonated device. The MAC address of the mouse can be viewed in Android settings (it's random by default). Then set the advertisement data with:

```sh
spoofing-set-adv-data name="MX Master 3" appearance=962
```

Where the values depend on the impersonated device (in our case, a Logitech MX Master 3 mouse). Then, specify a crafted security level for the security request with:

```sh
spoofing-set-authreq mitm=1 bond=1 sc=1 keypress=1
```

By setting all values to 1, we use the maximum authreq value, thereby maximizing the chance of triggering re-pairing. In cases such as the NimBLE implementation bug, one could set \texttt{bond=0} to trigger re-pairing regardless of other values. Then, by running:

```sh
security-set-data mitm=0 sc=0 keysize=7
```

The user can modify the actual re-pairing parameters and force the lowest possible security settings. Lastly, to toggle encryption rejection in the Controller, the user shall use:

```sh
blerp-set-flag val=1
```

Where `val` changes depending on the target device. For example, Apple devices require two rejections, while others require only one. After configuring the stack, the user can start advertising via the `advertise` command and wait for the victim to connect. Once the victim connects, the attack starts automatically. Depending on the target device and re-pairing configuration, there may be a visual prompt to confirm the operation, such as a dialog box with an OK button.


## Testing Central Impersonation

This attack maps to Section IV.C of the paper. The user is required to pair the target Peripheral with a Central device, as in the Peripheral Impersonation, with the only difference that, in this case, the Central must be turned off (or brought out of range).

Once the devices are ready, the user must configure the malicious device using the `set` and `security-set-data` as in the PI attack. Then, instead of advertising, the user shall initiate a connection using:

```sh
connect addr=MAC_Address
```

which automatically triggers a re-pairing attempt.

## Double-channel MitM

This attack maps to the double-channel MitM attack described in Section IV.D of the paper. Similar to the previous attacks, the two victim devices must be paired. Once this is done, to set up the MitM attack, the user shall:

1.  Connect two nRF52s to the laptop.
2.  From inside the _blerpae_ folder run `make erase && make boot-10056` on both boards, then run `make hci-mitm` once. This will perform a clean install of the new firmware on the boards.
3.  Modify `python-host/mitm.py` and insert the correct name (Peripheral) and MAC address (Central) in the main block, then run `sudo .venv/bin/python python-host/mitm.py`.

Now the user must disconnect the two legitimate devices by turning off Bluetooth on the Central. Once this is done, the attack will proceed as follows:

1.  The malicious Peripheral copies the advertisement data from the legitimate Peripheral.
2.  The malicious Central connects to the legitimate Peripheral, blocking its advertising.
3.  The malicious Peripheral begins advertising using the spoofed data.
4.  The user turns the legitimate Central's Bluetooth on again.
5.  The legitimate Central connects to the attacker's Peripheral, starting the MitM attack. The legitimate Central may be prompted with a Yes/No dialog box to confirm the connection.

## Testing Hardened Re-pairing

To test the hardened re-pairing the user must first install a patched NimBLE stack on one of the nRF52s and use the other one as the attacker. To set up the victim devices, inside the _blerpae_ folder run `apply_fixes_patch.sh` and then install the fixed stack using `make central` (if testing Peripheral impersonation) or `make peripheral` (if testing Central impersonation). The tests follow the same steps outlined previously for the attacks, including the securtiy level downgrade.


## Testing Authenticated Re-pairing

The authenticated re-pairing protocol can be verified using ProVerif. For download and installation please refer to the [official website](https://bblanche.gitlabpages.inria.fr/proverif/). Once installed, from the main _blerp_ repository run:

```sh
proverif formal/blerp_fixes.pv
```

The model contains two queries: the first one proves integrity and authentication of the re-pairing Pairing Key and it should evaluate to _true_, while the second one is a simple sanity check to show that the protocol ends correctly and it should evaluate to _false_. The ProVerif verification summary should reflect the one below:

```
Query inj-event(end_B(k)) ==> inj-event(end_A(k)) is true.

Query not (event(end_A(k)) && event(end_B(k))) is false.
```