# Quickstart

1. clone the repo
2. run `git config --local core.hooksPath githooks`
3. install perf `sudo apt install linux-tools-common linux-tools-generic linux-tools-$(uname -r)`
4. retrieve [FlameGraph](https://github.com/brendangregg/FlameGraph) on your system
   - create a local file `.FlameGraphDir` and write FlameGraph location
5. clone and install system-wide [wolfSSL](https://github.com/wolfSSL/wolfssl.git)
   - enable `aesni`, `intelasm`, `aesctr`, `aescbc`, `aesecb`
   - e.g., `./configure --enable-aesni --enable-intelasm --enable-aesctr --enable-aescbc CFLAGS="-DHAVE_AES_ECB"`
6. run `make` to build `keymix`
7. run `make k` to build and run `keymix`

# Workflow

+ `clang-format` is executed as a pre-commit hook
+ formatted files are highlighted in red and stored in the working directory
+ commit is aborted, the changes must be re-staged
+ only C/C++ source files are currently formatted
