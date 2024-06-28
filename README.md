# Quickstart

1. clone the repo
2. run `git config --local core.hooksPath githooks`
3. install perf `sudo apt install linux-tools-common linux-tools-generic linux-tools-$(uname -r)`
4. retrieve [FlameGraph](https://github.com/brendangregg/FlameGraph) on your system
   - create a local file `.FlameGraphDir` and write FlameGraph location
5. clone and install system-wide [wolfSSL](cd ..; git clone https://github.com/wolfSSL/wolfssl.git)
   - enable `aesni`, `intelasm`, `aesctr`, `aescbc`, `aesecb`
6. run `make` to build `keymix`
7. run `make k` to build and run `keymix`
