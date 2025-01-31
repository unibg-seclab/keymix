projroot=$(git rev-parse --show-toplevel)

echo "[*] Look into https://github.com/BLAKE3-team/BLAKE3/tree/master/c for the best compilation for your cpu architecture"
cd $projroot/deps/BLAKE3
git submodule update --init
cd c
gcc -shared -O3 -o libblake3.so blake3.c blake3_dispatch.c blake3_portable.c \
  	  blake3_sse2_x86-64_unix.S blake3_sse41_x86-64_unix.S blake3_avx2_x86-64_unix.S \
  	  blake3_avx512_x86-64_unix.S
echo "[*] Installing BLAKE3 library in /usr/local/lib ..."
sudo mkdir -p /usr/local/include/blake3
sudo cp -r blake3.h /usr/local/include/blake3/blake3.h
sudo chown root:root libblake3.so
sudo mv libblake3.so /usr/local/lib/libblake3.so
echo "[*] Updating shared library cache ..."
sudo ldconfig
cd $projroot/deps
