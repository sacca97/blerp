#!/bin/bash

# Create newt project
newt new blerp_poc

sed -i.bak '/repository\.apache-mynewt-core:/,/^$/ s/^\([[:space:]]*vers:[[:space:]]*\)[0-9]*\.[0-9]*\.[0-9]*$/\11.12.0/' blerp_poc/project.yml

cp -r apps/bleshell blerp_poc/apps/bleshell
cp -r targets/nrf52_boot blerp_poc/targets/nrf52_boot
cp -r targets/nrf52_blecent blerp_poc/targets/nrf52_blecent
cp -r targets/nrf52_hci blerp_poc/targets/nrf52_hci
cp -r patches blerp_poc/patches
cp -r python-host blerp_poc/python-host

cp apply_fixes_patch.sh blerp_poc/apply_fixes_patch.sh
cp apply_attacks_patch.sh blerp_poc/apply_attacks_patch.sh
cp Makefile blerp_poc/Makefile

cp erase.jlink blerp_poc/erase.jlink

python -m venv blerp_poc/.venv
source blerp_poc/.venv/bin/activate
pip install -r blerp_poc/python-host/requirements.txt
deactivate

cd blerp_poc
newt upgrade
