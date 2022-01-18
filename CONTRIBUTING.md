Thank you for your contribution to `cryptography-libsodium`! While there is no
Contributor License Agreement (CLA) to sign, we _do_ need you to read the
following instructions before you contribute.

## Code of Conduct

We need you to read, acknowledge, and abide by our [Code of Conduct][CoC].

### Pull Requests

When making a PR, ensure that you have a Github issue that explains the context
for your changes.

### Formatting and linting

We have a git hook in place to ensure the following formatting and linting tools
are being used:

* All Haskell source files are formatted with
  [`ormolu`](https://hackage.haskell.org/package/ormolu);
* All Haskell source files are linted with 
  [HLint](https://hackage.haskell.org/package/hlint), as per the `.hlint.yaml` 
  configuration file.
* The Cabal file is formatted with
  [`cabal-fmt`](https://github.com/phadej/cabal-fmt)

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

[CoC]: https://github.com/haskell-cryptography/cryptography-libsodium/blob/master/CODE_OF_CONDUCT.md
[Ticket]: https://github.com/haskell-cryptography/cryptography-libsodium/issues/new
