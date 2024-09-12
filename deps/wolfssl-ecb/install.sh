#!/bin/bash

set -e
srcdir="$(pwd)/src"
[ -d "$srcdir" ] || mkdir -p "$srcdir"

source "./PKGBUILD"

parts=(${source//::/ })

out="${parts[0]}"
if [ -f "$out" ]; then
  echo "Sources already downloaded"
else
  wget -O "$out" "${parts[1]}"
  tar -xvf "$out" -C "$srcdir"
fi

build
check

cd "$srcdir/$_pkgname-$pkgver-stable"
sudo make install
