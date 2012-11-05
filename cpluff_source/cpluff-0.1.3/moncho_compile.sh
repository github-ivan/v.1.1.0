#!/bin/sh
make clean
chmod +x configure
echo "./configure --prefix=$(cd ../.. ; echo "$(pwd)/cpluff")"
./configure --prefix=$(cd ../.. ; echo "$(pwd)/cpluff")
echo "make install"
make install
