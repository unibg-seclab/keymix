#!/bin/bash

set -e
srcdir="$(pwd)/src"
[ -d "$srcdir" ] || mkdir -p "$srcdir"

source "./PKGBUILD"

parts=(${source//::/ })

out="${parts[0]}"
wget -O "$out" "${parts[1]}"
tar -xvf "$out" -C "$srcdir"

build

cd "$srcdir/$_pkgname-$pkgver-stable"
sudo make install
