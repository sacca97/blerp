#!/bin/bash

CURRENT_DIR_COMMAND=$(pwd)

cd repos/apache-mynewt-nimble
git stash
git checkout 675452b628

git apply --reject --whitespace=fix "$CURRENT_DIR_COMMAND"/patches/blerp.patch

cd "$CURRENT_DIR_COMMAND"
cd repos/apache-mynewt-core
git stash
git apply --reject --whitespace=fix "$CURRENT_DIR_COMMAND"/patches/core.patch
