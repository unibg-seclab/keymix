pkgname=keymix-git
_pkgname=keymix
pkgver=1.0.0
pkgrel=1
pkgdesc="Keymix: an algorithm for encrypting resources using large keys"
arch=(x86_64)
url="https://github.com/unibg-seclab/keymix"
license=(GPL-2.0-or-later)
depends=(wolfssl-ecb openssl xkcp-git blake3)
makedepends=(git gcc help2man)
provides=(keymixer libkeymix.so)
source=("${_pkgname}::git+ssh://git@github.com/unibg-seclab/${_pkgname}.git")
sha512sums=('SKIP')

_bin=keymixer
_lib=libkeymix.so
_main=main

build() {
	cd "${_pkgname}"
	make "${_lib}"
	make "${_bin}"
	make "${_main}"
	mkdir -p doc
}

package() {
	cd "${_pkgname}"
	install -Dm 0777 "$srcdir/${_pkgname}/${_bin}" "$pkgdir/usr/bin/${_bin}"
	install -Dm 0777 "$srcdir/${_pkgname}/${_main}" "$pkgdir/usr/bin/${_bin}-quicktest"
	install -Dm 0755 "$srcdir/${_pkgname}/${_lib}" "$pkgdir/usr/lib/${_lib}"

	mkdir -p "$pkgdir/usr/share/man/man1"
	help2man --no-info --no-discard-stderr ./keymixer > "$pkgdir/usr/share/man/man1/keymixer.1"

	mkdir -p "$pkgdir/usr/include/keymix"
	install -Dm 0644 $srcdir/${_pkgname}/include/* "$pkgdir/usr/include/keymix/"
}
