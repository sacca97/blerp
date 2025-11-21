#!/bin/bash

CURRENT_DIR_COMMAND=$(pwd)

cd repos/apache-mynewt-nimble
git stash
git checkout 675452b628

git apply --reject --whitespace=fix "$CURRENT_DIR_COMMAND"/patches/blerp-fixes.patch
