Thank you for your contribution to cryptography-libsodium! There is no Contributor License Agreement (CLA) to sign,
but we need you to read this document when you open your PR or your issue:

## Contributing

We need you to read and acknowledge our [Code of Conduct][CoC] document.

### Pull Requests

You need to

* Read this document
* Have a ticket that you can relate the PR to, so that we can have some context for your change
* Provide screenshots of before/after if you change the UI.

### Questions 

Open a thread in the [Questions][Questions board] discussion board. You'll get help from everyone in the community.

### Issues & Bugs

Open a [Ticket][Ticket] and tell us what you can about your problem.

## Code style

### C FFI

* The [CApiFFI convention](https://www.haskell.org/ghc/blog/20210709-capi-usage.html) must be used at all times.
* The datatypes from [`Foreign`](https://hackage.haskell.org/package/base/docs/Foreign.html) must be used when
getting results from C, like `CInt` in favour of `Int`.
  Example: 
  - ❌ `foreign export ccall sodium_init :: IO Int`

  - ✅ `foreign import capi "sodium.h sodium_init"  c_sodium_init :: IO CInt`

[CoC]: https://github.com/haskell-cryptography/cryptography-libsodium/blob/master/CODE_OF_CONDUCT.md
[Ticket]: https://github.com/haskell-cryptography/cryptography-libsodium/issues/new
