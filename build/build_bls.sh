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
cd $BLS_ROOT/linux/src/bls
$MAKE 

# copy bls  header and lib files to destination directory
cp -r $BLS_ROOT/linux/src/bls/include/bls $BLS_ROOT/linux/include/
rm -rf $BLS_ROOT/linux/src/bls/ffi
cp $BLS_ROOT/linux/src/bls/lib/*.a $BLS_ROOT/linux/lib/

# copy mcl header and lib files to destination directory
cd $BLS_ROOT/linux/src/mcl
rm -rf ffi
cp -r $BLS_ROOT/linux/src/mcl/include/mcl $BLS_ROOT/linux/include/
cp -r /$BLS_ROOT/linux/src/mcl/include/cybozu $BLS_ROOT/linux/include/
cp $BLS_ROOT/linux/src/mcl/lib/*.a $BLS_ROOT/linux/lib/
