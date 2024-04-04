# sel [![CI](https://github.com/haskell-cryptography/libsodium-bindings/actions/workflows/sel.yml/badge.svg)](https://github.com/haskell-cryptography/libsodium-bindings/actions/workflows/sel.yml) [![made with Haskell](https://img.shields.io/badge/Made%20in-Haskell-%235e5086?logo=haskell&style=flat-square)](https://haskell.org)


Sel is the library for casual users by the [Haskell Cryptography Group](https://haskell-cryptography.org).
It builds on [Libsodium](https://doc.libsodium.org), a reliable and audited library for common operations.

## Hashing

|                              Purpose                                 | Module                         |
|----------------------------------------------------------------------|--------------------------------|
| Hash passwords                                                       | [Sel.Hashing.Password](https://hackage.haskell.org/package/sel-0.0.1.0/candidate/docs/Sel-Hashing-Password.html)         |
| Verify the integrity of files and hash large data                    | [Sel.Hashing](https://hackage.haskell.org/package/sel-0.0.1.0/candidate/docs/Sel-Hashing.html)                  |
| Hash tables, bloom filters, fast integrity checking of short input   | [Sel.Hashing.Short](https://hackage.haskell.org/package/sel-0.0.1.0/candidate/docs/Sel-Hashing-Short.html)            |

## Secret key / Symmetric cryptography

|                              Purpose                                 | Module                         |
|----------------------------------------------------------------------|--------------------------------|
| Authenticate a message with a secret key                             | [Sel.SecretKey.Authentication](https://hackage.haskell.org/package/sel-0.0.1.0/candidate/docs/Sel-SecretKey-Authentication.html) |
| Encrypt and sign data with a secret key                              | [Sel.SecretKey.Cipher](https://hackage.haskell.org/package/sel-0.0.1.0/candidate/docs/Sel-SecretKey-Cipher.html)         |
| Encrypt a stream of messages                                         | [Sel.SecretKey.Stream](https://hackage.haskell.org/package/sel-0.0.1.0/candidate/docs/Sel-SecretKey-Stream.html)         |

## Public and Secret key / Asymmetric cryptography

|                              Purpose                                 | Module                         |
|----------------------------------------------------------------------|--------------------------------|
| Sign and encrypt with my secret key and my recipient's public key    | [Sel.PublicKey.Cipher](https://hackage.haskell.org/package/sel-0.0.1.0/candidate/docs/Sel-PublicKey-Cipher.html)         |
| Sign and encrypt an anonymous message with my recipient's public key | [Sel.PublicKey.Seal](https://hackage.haskell.org/package/sel-0.0.1.0/candidate/docs/Sel-PublicKey-Seal.html)           |
| Sign with a secret key and distribute my public key                  | [Sel.PublicKey.Signature](https://hackage.haskell.org/package/sel-0.0.1.0/candidate/docs/Sel-PublicKey-Signature.html)      |

## HMAC message authentication

|                              Purpose                                 | Module                         |
|----------------------------------------------------------------------|--------------------------------|
| HMAC-256                                                             | [Sel.HMAC.SHA256](https://hackage.haskell.org/package/sel-0.0.1.0/candidate/docs/Sel-HMAC-SHA256.html)              |
| HMAC-512                                                             | [Sel.HMAC.SHA512](https://hackage.haskell.org/package/sel-0.0.1.0/candidate/docs/Sel-HMAC-SHA512.html)              |
| HMAC-512-256                                                         | [Sel.HMAC.SHA512_256](https://hackage.haskell.org/package/sel-0.0.1.0/candidate/docs/Sel-HMAC-SHA512_256.html)          |

## Legacy SHA2 constructs

|                              Purpose                                 | Module                         |
|----------------------------------------------------------------------|--------------------------------|
| SHA-256                                                              | [Sel.Hashing.SHA256](https://hackage.haskell.org/package/sel-0.0.1.0/candidate/docs/Sel-Hashing-SHA256.html)           |
| SHA-512                                                              | [Sel.Hashing.SHA512](https://hackage.haskell.org/package/sel-0.0.1.0/candidate/docs/Sel-Hashing-SHA512.html)           |
| Scrypt                                                               | [Sel.Scrypt](https://hackage.haskell.org/package/sel-0.0.1.0/candidate/docs/Sel-Scrypt.html)                   |
