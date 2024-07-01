#!/bin/sh

set -e
srcdir="$(pwd)/src"

source "./PKGBUILD"

build
check

cd "$srcdir/$pkgname-$pkgver-stable"
sudo make install
