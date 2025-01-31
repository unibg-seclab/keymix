projroot=$(git rev-parse --show-toplevel)
XKCP_TARGET="AVX2"

echo "[*] Look into https://github.com/XKCP/XKCP for the best compilation target for your cpu architecture (default: AVX2)"
cd $projroot/deps/XKCP
git submodule update --init
make $(XKCP_TARGET)/libXKCP.so
echo "[*] Installing XKCP library in /usr/local/lib ..."
sudo mkdir -p /usr/local/include/xkcp
sudo cp -r bin/$(XKCP_TARGET)/libXKCP.so.headers/* /usr/local/include/xkcp
sudo cp bin/$(XKCP_TARGET)/libXKCP.so /usr/local/lib/libXKCP.so
echo "[*] Updating shared library cache ..."
sudo ldconfig
cd -
