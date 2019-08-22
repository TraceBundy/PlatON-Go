#!/usr/bin/env bash

if [ ! -f "build/build_deps.sh" ]; then
    echo "$0 must be run from the root of the repository."
    exit 2
fi

PLATON_ROOT=`pwd`
BLS_ROOT=$PLATON_ROOT/crypto/bls

if [ `expr substr $(uname -s) 1 5` != "Linux" ]; then
    echo "not support system $(uname -s)"
    exit 1
fi

# sudo apt install libgmp-dev
# sudo apt install libssl-dev
# the above are prerequisites

if [ "`ls $BLS_ROOT/linux`" = "" ]; then
    # pull code of bls, mcl and cybozulib_ext
    cd $BLS_ROOT
    mkdir -p linux
    cd linux
    mkdir -p include
    mkdir -p lib
    mkdir -p src
    cd src
    git clone https://github.com/herumi/mcl.git
    git clone https://github.com/herumi/bls.git
    # below is only for Windows
    # git clone https://github.com/herumi/cybozulib_ext.git
fi

set -e

# Build and test bls lib
MAKE="make"
cd bls
$MAKE test

# copy bls  header and lib files to destination directory
cp -r ./include/bls $BLS_ROOT/linux/include/
cp ./lib/*.a $BLS_ROOT/linux/lib/

# copy mcl header and lib files to destination directory
cd ../mcl
cp -r ./include/mcl $BLS_ROOT/linux/include/
cp -r ./include/cybozu $BLS_ROOT/linux/include/
cp ./lib/*.a $BLS_ROOT/linux/lib/
