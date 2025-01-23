Thank you for your contribution to `sel`! While there is no
Contributor License Agreement (CLA) to sign, we _do_ need you to read the
following instructions before you contribute.

## Code of Conduct

We need you to read, acknowledge, and abide by our [Code of Conduct][CoC].

### Pull Requests

When making a PR, ensure that you have a Github issue that explains the context for your changes.

## Code Style

### C FFI

* The [CApiFFI convention](https://www.haskell.org/ghc/blog/20210709-capi-usage.html) must be used at all times.
* The datatypes from [`Foreign`](https://hackage.haskell.org/package/base/docs/Foreign.html) must be used when
getting results from C, like `CInt` in favour of `Int`.
  Example:
  - ❌ `foreign export ccall sodium_init :: IO Int`

  - ✅ `foreign import capi "sodium.h sodium_init"  c_sodium_init :: IO CInt`

### Formatting and linting

We have a git hook in place to ensure the following formatting and linting tools
are being used:

* All Haskell source files are formatted with
  [`fourmolu`](https://flora.pm/packages/@hackage/fourmolu/0.17.0.0) v0.17.0.0;
* All Haskell source files are linted with
  [`hlint` v3.8](https://flora.pm/packages/@hackage/hlint/3.8), as per the `.hlint.yaml`
  configuration file.
* The Cabal file is formatted with
  [`cabal-gild` v1.5.0.1](https://flora.pm/packages/@hackage/cabal-gild/1.5.0.1)

To ensure that you are using the git hook, run the following, once:

```
git config core.hooksPath .githooks
```

You can also use the provided `Makefile` by running `make init`.

### Questions

Open a thread in the [Questions][Questions board] discussion board. That way,
you can get help from everyone in the community.

### Issues & Bugs

Open an [issue][Ticket] and tell us what you can about your problem.

[CoC]: https://github.com/haskell-cryptography/governance/blob/master/CODE_OF_CONDUCT.md
[Ticket]: https://github.com/haskell-cryptography/libsodium-bindings/issues/new
[Questions board]: https://github.com/haskell-cryptography/libsodium-bindings/discussions/categories/q-a
