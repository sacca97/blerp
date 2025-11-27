model?=10056

ceid?=0000000000 #board 1
peid?=0000000000 #board 2
devid?=0000000000 #generic

all: central peripheral


update:
	newt upgrade -f

#PERIPHERAL
targetprph10056:
	@echo "target.app: \""apps/bleprph"\"" > targets/nrf52_bleprph/target.yml
	@echo "target.bsp: \""@apache-mynewt-core/hw/bsp/nordic_pca10056"\"" >> targets/nrf52_bleprph/target.yml
	@echo "target.build_profile: optimized" >> targets/nrf52_bleprph/target.yml

targetprph10040:
	@echo "target.app: \""apps/bleprph"\"" > targets/nrf52_bleprph/target.yml
	@echo "target.bsp: \""@apache-mynewt-core/hw/bsp/nordic_pca10040"\"" >> targets/nrf52_bleprph/target.yml
	@echo "target.build_profile: optimized" >> targets/nrf52_bleprph/target.yml

set-prph-target-10056:
	@echo "target.app: \""apps/bleprph"\"" > targets/nrf52_bleprph/target.yml
	@echo "target.bsp: \""@apache-mynewt-core/hw/bsp/nordic_pca10056"\"" >> targets/nrf52_bleprph/target.yml
	@echo "target.build_profile: optimized" >> targets/nrf52_bleprph/target.yml

# HID (Mouse/Keyboard)
build-hid:
	newt clean nrf52_blehid
	newt build nrf52_blehid
	newt create-image nrf52_blehid 1.0.0

load-hid:
	newt load nrf52_blehid --extrajtagcmd "-select usb=$(peid)"

hid: set-prph-target-10056 build-hid load-hid

# Peripheral
build-prph:
	newt clean nrf52_bleprph
	newt build nrf52_bleprph
	newt create-image nrf52_bleprph 1.0.0

load-prph:
	newt load nrf52_bleprph --extrajtagcmd "-select usb=$(peid)"

peripheral: set-prph-target-10056 build-prph load-prph

# Central
set-cent-target-10056:
	@echo "target.app: \""apps/bleshell"\"" > targets/nrf52_blecent/target.yml
	@echo "target.bsp: \""@apache-mynewt-core/hw/bsp/nordic_pca10056"\"" >> targets/nrf52_blecent/target.yml
	@echo "target.build_profile: optimized" >> targets/nrf52_blecent/target.yml

build-cent:
	newt clean nrf52_blecent
	newt build nrf52_blecent
	newt create-image nrf52_blecent 1.0.0

load-cent:
	newt load nrf52_blecent --extrajtagcmd "-select usb=$(ceid)"

central: set-cent-target-10056 build-cent load-cent

all: central peripheral

# HCI DevBoard

hci-devboard:
	newt clean nrf52_hci
	newt build nrf52_hci
	newt create-image nrf52_hci 1.0.0
	newt load nrf52_hci --extrajtagcmd "-select usb=$(peid)"

hci-mitm:
	newt clean nrf52_hci
	newt build nrf52_hci
	newt create-image nrf52_hci 1.0.0
	newt load nrf52_hci --extrajtagcmd "-select usb=$(peid)"
	newt load nrf52_hci --extrajtagcmd "-select usb=$(ceid)"



#BOOT
boot-10056:
	@echo "target.app: \""@mcuboot/boot/mynewt"\"" > targets/nrf52_boot/target.yml
	@echo "target.bsp: \""@apache-mynewt-core/hw/bsp/nordic_pca10056"\"" >> targets/nrf52_boot/target.yml
	@echo "target.build_profile: optimized" >> targets/nrf52_boot/target.yml
	newt build nrf52_boot
	newt load nrf52_boot --extrajtagcmd "-select usb=$(devid)"

boot10040:
	@echo "target.app: \""@mcuboot/boot/mynewt"\"" > targets/nrf52_boot/target.yml
	@echo "target.bsp: \""@apache-mynewt-core/hw/bsp/nordic_pca10040"\"" >> targets/nrf52_boot/target.yml
	@echo "target.build_profile: optimized" >> targets/nrf52_boot/target.yml
	newt build nrf52_boot
	newt load nrf52_boot --extrajtagcmd "-select usb=$(devid)"


# NRF53
nrf53-recover:
	nrfjprog --eraseall
	nrfjprog --recover --coprocessor CP_NETWORK
	nrfjprog --recover
	nrfjprog --erasepage 0x01000000-0x01021000 --coprocessor CP_NETWORK

nrf53-boot-netcore:
	newt build nrf53_boot_net
	newt load nrf53_boot_net

nrf53-boot:
	newt build nrf53_boot
	newt load nrf53_boot

nrf53-prph:
	newt build nrf53_bleprph
	newt create-image nrf53_bleprph timestamp
	newt load nrf53_bleprph

nrf53-all: nrf53-boot-netcore nrf53-boot nrf53-prph

#DONGLE
dongle-boot:
	newt build nordic_pca10059_boot
	newt load nordic_pca10059_boot

dongle-hci:
	newt clean nordic_pca10059_hci
	newt build nordic_pca10059_hci
	newt create-image nordic_pca10059_hci 1.0.0

dongle-load:
	newt load nordic_pca10059_hci

#UTILS
clean:
	@rm -rf bin/*
	@rm -rf repos/* repos/.configs repos/.gdb_out

erase:
	JLinkExe -SelectEmuBySN $(devid)  -if SWD -speed 4000 -commanderscript erase.jlink
