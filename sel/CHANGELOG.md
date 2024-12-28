# CHANGELOG

## sel-0.0.3.0

### New `Sel.PublicKey.Signature` API [#166][166]
#### Additions
* Adds `decodePublicKeyHexByteString` and `encodePublicKeyHexByteString` for de/serialization of `PublicKey`s
* Adds `UnsafeSecretKey` newtype to signal risky operations
* Adds `decodeSecretKeyHexByteString` and `encodeSecretKeyHexByteString` for de/serialization of `SecretKey`s (with encoding via `UnsafeSecretKey`)
* Adds `unsafeSecretKeyHexByteString` for direct encoding of `SecretKey`s (prefer explicit use of `UnsafeSecretKey`)
* Adds `publicKey` for extracting the `PublicKey` from a `SecretKey`
* Adds `PublicKeyExtractionException`, thrown by `publicKey` on failure
* Adds `KeyPair PublicKey SecretKey` and `keyPair :: IO KeyPair` along with accessors `public` and `secret`; `OverloadedRecordDot` is also supported
* Adds `signWith`, a flipped version of `signMessage`
* Adds `SignatureVerification` for chaining transformations on verified messages
* Adds `verifiedMessage` for extracting a message with verification data
* Adds `signature` and `unverifiedMessage` for extracting signature and message parts, respectively, without signature verification
* Adds `signedMessage` for constructing a `SignedMessage` from a message and a detached signature
#### Removals
* `Ord SecretKey` is vulnerable to timing attacks and has been removed; this instance is available on `UnsafeSecretKey`
#### Deprecations
``` diff
- generateKeyPair :: IO (PublicKey, SecretKey)
+ keyPair :: IO KeyPair
```

``` diff
- openMessage :: SignedMessage -> PublicKey -> Maybe StrictByteString
+ verifiedMessage :: SignedMessage -> PublicKey -> SignatureVerification StrictByteString
```

``` diff
- getSignature :: SignedMessage -> StrictByteString
+ signature :: SignedMessage -> StrictByteString
```

``` diff
- unsafeGetMessage :: SignedMessage -> StrictByteString
+ unverifiedMessage :: SignedMessage -> StrictByteString
```

``` diff
- mkSignature :: StrictByteString -> StrictByteString -> SignedMessage
+ signedMessage :: StrictByteString -> StrictByteString -> SignedMessage
```

#### Fixes
* `Eq SecretKey` uses constant-time comparison to resist timing attacks

### Hexadecimal codec utilities [#166][166]
#### Additions
* Adds `encodeHexByteString'`, a configurable encoder for key material, and `encodeHexByteString` using a default copying encoder
* Adds `decodeHexByteString'`, a configurable decoder for key material, and `decodeHexByteString` using a default copying decoder
* Adds `showHexEncoding`, for defining `Show` instances in terms of `encodeHexByteString`
* Adds `KeyMaterialDecodeError` and validation functions for pre-processing `StrictByteString` inputs
* Adds `KeyPointerSize` for defining a pointer size for key material
* Adds `keyPointerLength`, the `Int` length of a key material pointer
* Adds `keyPointer` for allocating a `ForeignPtr CUChar` to contain key material
* Adds `KeyPointer`, a `deriving via` utility wrapper for deriving `Eq` and `Ord` instances with configurable comparison strategies (short-circuiting or constant-time) for types with a defined `KeyPointerSize`

[166]: https://github.com/haskell-cryptography/libsodium-bindings/pull/166

## sel-0.0.2.0

* Add usages of `secureMain` in examples
* Depends on libsodium-bindings-0.0.2.0

