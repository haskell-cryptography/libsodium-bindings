# CHANGELOG

## sel-0.2.0.0

* Add binary conversion pairs (`xToBinary` / `binaryToX`) for every key, hash, nonce, authentication tag and secret-stream header in the `sel` package [#205](https://github.com/haskell-cryptography/libsodium-bindings/issues/205)
* Deprecate `unsafeAuthenticationKeyToBinary` in favour of `authenticationKeyToBinary`; this also fixes `Sel.HMAC.SHA512_256.unsafeAuthenticationKeyToBinary` erroneously returning hex-encoded bytes
* Attach the custom warning category `x-unsafe-serialization` to the binary serialization helpers; consumers must silence it with `-Wno-x-unsafe-serialization` (GHC ≥ 9.8)

## sel-0.1.0.0

* Consistently rename ciphertext-related types and functions [#182](https://github.com/haskell-cryptography/libsodium-bindings/pull/182)
* Add support for additional data (AD) in `Sel.SecretKey.Stream` [#183](https://github.com/haskell-cryptography/libsodium-bindings/pull/183)
* Define some cryptographic functions in sel as pure [#189](https://github.com/haskell-cryptography/libsodium-bindings/pull/189)

## sel-0.0.3.0

* Add constant time hex encoding [#176](https://github.com/haskell-cryptography/libsodium-bindings/pull/176)
* Support `text-display` 1.0.0.0
* Replace usages of `memcpy` with `Foreign.copyBytes` [#172](https://github.com/haskell-cryptography/libsodium-bindings/pull/172)
* Add constant-time pointer comparison [#171](https://github.com/haskell-cryptography/libsodium-bindings/pull/171)
* (Internal) Add constant-time Eq, use Scoped for internals [#169](https://github.com/haskell-cryptography/libsodium-bindings/pull/169)
* Cleanup, allow more versions of `tasty` [#168](https://github.com/haskell-cryptography/libsodium-bindings/pull/168)
* (Internal) Add `Scoped` for better readability of nested continuations [#167](https://github.com/haskell-cryptography/libsodium-bindings/pull/167)
* Update hedgehog [#180](https://github.com/haskell-cryptography/libsodium-bindings/pull/180)

## sel-0.0.2.0

* Add usages of `secureMain` in examples
* Depends on libsodium-bindings-0.0.2.0
