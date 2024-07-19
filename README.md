# Keymix

## Setup instructions

- Install OpenSSL (packaged version for your system is fine)
- Install wolfSSL with `make wolfssl`
- Compile everything with `make`

## CLI

TODO

## Development

### Code style

The file `.clang-format` should work out of the box. In `githooks` you'll find
some git hooks to enable with `git config --local core.hooksPath githooks`,
which formats the project before a commit and modified files are brought back
from staging.

### Configuration

Change the values in `config.h`. In particular:

- `DEBUG` is used to enable debug-time checks
- `DISABLE_LOG` to disable all logging (removing the code too)
- `LOG_LEVEL` which can be set to either `LOG_DEBUG` or `LOG_INFO` and acts
   as a filter for which logs to show

Logs are shown on `stderr`.

### Performance and tests

1. Perf and flame graphs
   - Install `perf`
   - Clone [FlameGraph](https://github.com/brendangregg/FlameGraph)
   - Write the install path in the `.FlameGraphDir` file
   - `make perf`, `make perf-report`, and `make perf-flamegraph`
2. Automatic performance tests
   - `make test` to compile
   - `make run-test` to run them
   - `make daemon` to run tests as a daemon (they take quite a lot of time)
3. Verifying equivalence between various implementations (i.e., sanity check)
   - `make verify` and then run `./verify`
