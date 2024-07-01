# Quickstart

1. Clone the repo
2. Run `git config --local core.hooksPath githooks`
3. Run `git config --local pull.rebase true`
4. Install `perf`
   - May be necessary to install `linux-tools-common linux-tools-generic linux-tools-$(uname -r)` or the equivalent
     in your distro
5. Retrieve [FlameGraph](https://github.com/brendangregg/FlameGraph) on your system,
   write install path into `.FlameGraphDir`
6. Clone and install system-wide [wolfSSL](https://github.com/wolfSSL/wolfssl.git)
   - Enable `aesni`, `intelasm`, `aesctr`, `aescbc`, `aesecb`
   - Use `pkgs/wolfssl-ecb/install.sh` if you want

# Workflow

- `clang-format` is executed as a pre-commit hook
- Formatted files are highlighted in red and stored in the working directory
- Commit is aborted, the changes must be re-staged
- Only C/C++ source files are currently formatted
