echo "[*] Installing wolfSSL"
cd wolfssl-ecb && ./install.sh
echo "[*] Installing BLAKE3"
cd blake3 && ./install.sh
echo "[*] Installing XKCP"
cd xkcp && ./install.sh
