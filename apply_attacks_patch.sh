#!/bin/bash

CURRENT_DIR_COMMAND=$(pwd)

cd repos/apache-mynewt-nimble
git checkout 675452b628

git apply --reject --whitespace=fix "$CURRENT_DIR_COMMAND"/patches/blerp.patch
