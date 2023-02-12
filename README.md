# Sodium Bindings [![made with Haskell](https://img.shields.io/badge/Made%20in-Haskell-%235e5086?logo=haskell&style=flat-square)](https://haskell.org)

The Haskell Cryptography Group presents its suite of libsodium packages:

| Package                  | Status           |
|--------------------------|------------------|
| [sel][sel]               | ![sel-ci]        |
| [libsodium-bindings][lb] | ![lb-ci]         |

## Comparison with other libraries

|                    | Description                                | Dependencies                                                                 | GHC Support        | FFI Convention                 |
|--------------------|--------------------------------------------|------------------------------------------------------------------------------|--------------------|--------------------------------|
| `libsodium-bindings` | Low-level FFI bindings                     | `base`                                                                     | Starts with 8.10.7 | Recommended `capi` convention  |
| `sel`                | High-level Haskell interface               | `base`, `base16`,  `bytestring`, `text` `text-display`, `libsodium-bindings` | Starts with 8.10.7 | Defers to `libsodium-bindings` |
| `saltine`            | Both FFI bindings and high-level interface | `base`, `bytestring` `deepseq`, `text`, `hashable`, `profunctors`            | Starts with 8.0.2  | Legacy `ccall` convention      |
| `libsodium`          | Low-level FFI bindings                     | `base`                                                                       | 8.6.5 to 8.10.1    | Legacy `ccall` convention      |
| `crypto-sodium`      | High-level Haskell interface               | `base`, `bytestring`, `random`, `cereal`, `libsodium`, `memory`,             | Unclear            | Defers to `libsodium`          |

[sel]: https://github.com/haskell-cryptography/libsodium-bindings/blob/main/sel/README.md
[sel-ci]: https://github.com/haskell-cryptography/libsodium-bindings/actions/workflows/sel.yml/badge.svg

[lb]: https://github.com/haskell-cryptography/libsodium-bindings/blob/main/libsodium-bindings/README.md
[lb-ci]: https://github.com/haskell-cryptography/libsodium-bindings/actions/workflows/libsodium-bindings.yml/badge.svg
