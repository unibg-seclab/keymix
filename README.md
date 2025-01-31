# Keymix

This is the official repo for the Keymix algorithm.

We offer both a shared C library with the necessary functions to use Keymix
in your code, and a CLI tool called `keymixer` to directly apply encryption
and decryption to files.

## Installing

### Arch Linux

We offer a `PKGBUILD` in the top directory that sets up the shared library
and the CLI tool.
Please note that you have to manually install the dependencies, their `PKGBUILD`
files are available at

- `deps/blake3/PKGBUILD`
- `deps/xkcp/PKGBUILD`
- `deps/wolfssl-ecb/PKGBUILD`

### Other systems

1. Install OpenSSL on your system (the packaged version is fine)
2. Install the remaining dependencies with `make deps`
3. Install Keymix with `install.sh` in the top directory

### Manual compilation

1. Install OpenSSL on your system (the packaged version is fine)
2. Install the remaining dependencies with `make deps`
3. Compile the desired features
   - `make` to only compile the code
   - `make libkeymix.so` for the shared library
   - `make keymixer` for the CLI tool
4. Install in your system the generated files, for example
   - `install -Dm 0777 keymixer /usr/bin/keymixer`
   - `install -Dm 0755 libkeymix.so /usr/lib/libkeymix.so`
   Note that install directories may be different for your distro

There are also install scripts for all manual dependencies

- `deps/blake3/install.sh`
- `deps/xkcp/install.sh`
- `deps/wolfssl-ecb/install.sh`

## Logs at runtime

By default, the code will output logs on `stderr`.
You can configure the specific behaviour and filters by changing the values
in `src/config.h`.
In particular:

- `DEBUG` is used to enable debug-time checks
- `DISABLE_LOG` to disable all logging (removing the code too)
- `LOG_LEVEL` which can be set to either `LOG_DEBUG` or `LOG_INFO` and acts
   as a filter for which logs to show

## Testing

1. Perf and flame graphs
   - Install `perf`
   - Clone [FlameGraph](https://github.com/brendangregg/FlameGraph)
   - Write the install path in the `.FlameGraphDir` file
   - `make perf`, `make perf-report`, and `make perf-flamegraph`
2. Automatic performance tests
   - `make test` to compile
   - `./test` to run them
   - `make daemon` to run tests as a daemon

   The tests write data to `data/out.csv` and `data/enc.csv`.
   Please note that they take quite a lot of time.
3. Verifying equivalence between various implementations (i.e., sanity check)
   - `make verify` and then run `./verify`

### Code style

The file `.clang-format` should work out of the box. In `githooks` you'll find
some git hooks to enable with `git config --local core.hooksPath githooks`,
which formats the project before a commit and modified files are brought back
from staging.
