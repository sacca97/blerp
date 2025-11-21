#!/bin/bash

# Create newt project
newt new blerpae

sed -i.bak '/repository\.apache-mynewt-core:/,/^$/ s/^\([[:space:]]*vers:[[:space:]]*\)[0-9]*\.[0-9]*\.[0-9]*$/\11.12.0/' blerpae/project.yml

cp -r apps/bleshell blerpae/apps/bleshell
cp -r targets/nrf52_boot blerpae/targets/nrf52_boot
cp -r targets/nrf52_blecent blerpae/targets/nrf52_blecent
cp -r targets/nrf52_hci blerpae/targets/nrf52_hci
cp -r patches blerpae/patches
cp -r python-host blerpae/python-host

cp fixes_patch.sh blerpae/fixes_patch.sh
cp attacks_patch.sh blerpae/attacks_patch.sh
cp Makefile blerpae/Makefile

cp erase.jlink blerpae/erase.jlink

python -m venv blerpae/.venv
source blerpae/.venv/bin/activate
pip install -r blerpae/python-host/requirements.txt
deactivate

cd blerpae
newt upgrade
