# Constellation Basic Functionality and Datatypes

**Constellation is under active development and has not undergone
rigorous security evaluation.  It cannot offer strong security
guarantees at present.**

This package contains common functionality and datatypes for the
Constellation distributed systems platform.  It is primarily intended
to serve as a home for things that don't clearly belong in another
package, would lead to spurious dependencies, or would cause
dependency cycles.

## Quicklinks

* [Developer documentation for `devel` branch](https://constellation-system.github.io/constellation-common/index.html)
* [Coverage reports for `devel` branch](https://constellation-system.github.io/constellation-common/coverage/index.html)
* [Contribution guide](https://github.com/constellation-system/constellation-common/blob/devel/CONTRIBUTING.md)

## Testing

Tests for this repository rely on generated X.509 certificates.  You
need to run the `gen_test_certs.sh` script once prior to testing.
Following that, the certificates should not need to be regenerated:

```sh
sh ./gen_test_certs.sh
cargo test
```