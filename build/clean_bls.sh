#!/usr/bin/env bash

set -e

if [ ! -f "build/clean_bls.sh" ]; then
    echo "$0 must be run from the root of the repository."
    exit 2
fi

PLATON_ROOT=`pwd`
BLS_ROOT=$PLATON_ROOT/crypto/bls

if [ `expr substr $(uname -s) 1 5` != "Linux" ]; then
    echo "not support system $(uname -s)"
    exit 1
fi

MAKE="make"

# Clean bls build files
cd $BLS_ROOT/linux/src/bls
$MAKE clean

# Clean mcl build files
cd $BLS_ROOT/linux/src/mcl
$MAKE clean

# Clean lib files previously copied into linux/lib
cd $BLS_ROOT/linux/lib
rm -f *.*

