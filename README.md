[![Safety Dance](https://img.shields.io/badge/unsafe-forbidden-success.svg)](https://github.com/rust-secure-code/safety-dance/)

# Rust Tapyrus Library

Library with support for de/serialization, parsing and executing on data
structures and network messages related to Tapyrus.

This repository is forked from [rust-bitcoin](https://github.com/rust-bitcoin/rust-bitcoin)

* De/serialization of Tapyrus protocol network messages
* De/serialization of blocks and transactions
* Script de/serialization
* Private keys and address creation, de/serialization and validation (including full BIP32 support)
* PSBT creation, manipulation, merging and finalization
* Pay-to-contract support as in Appendix A of the [Blockstream sidechains whitepaper](https://www.blockstream.com/sidechains.pdf)

For JSONRPC interaction with Tapyrus Core, it is recommended to use

## Installing Rust
Rust can be installed using your package manager of choice or
[rustup.rs](https://rustup.rs). The former way is considered more secure since
it typically doesn't involve trust in the CA system. But you should be aware
that the version of Rust shipped by your distribution might be out of date.
Generally this isn't a problem for `rust-tapyrus` since we support much older
versions (>=1.22) than the current stable one.

## Building
The library can be built and tested using [`cargo`](https://github.com/rust-lang/cargo/):

```
git clone git@github.com:chaintope/rust-tapyrus.git
cd rust-tapyrus
cargo build
```

You can run tests with:

```
cargo test
```

Please refer to the [`cargo` documentation](https://doc.rust-lang.org/stable/cargo/) for more detailed instructions. 

# Release Notes

See CHANGELOG.md


# Licensing

The code which was forked from rust-bitcoin is still CC0 1.0 Universal license and the code 
which was added and modified after forked is licensed as MIT License.
