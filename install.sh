_bin=keymixer
_lib=libkeymix.so

make "${_lib}"
make "${_bin}"
mkdir -p doc

install -Dm 0777 "${_bin}" "/usr/bin/${_bin}"
install -Dm 0777 "${_main}" "/usr/bin/${_bin}-quicktest"
install -Dm 0755 "${_lib}" "/usr/lib/${_lib}"

mkdir -p "/usr/share/man/man1"
help2man --no-info --no-discard-stderr ./keymixer > "/usr/share/man/man1/keymixer.1"

mkdir -p "/usr/include/keymix"
install -Dm 0644 include/* "/usr/include/keymix/"
