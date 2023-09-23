# Sodium Bindings [![made with Haskell](https://img.shields.io/badge/Made%20in-Haskell-%235e5086?logo=haskell&style=flat-square)](https://haskell.org)

The Haskell Cryptography Group presents its suite of libsodium packages:

| Package                  | Status                 |
|--------------------------|------------------------|
| [sel][sel]               | [![sel-badge]][sel-ci] |
| [libsodium‑bindings][lb] | [![lb-badge]][lb-ci]   |

## Comparison with other libraries

| Name                 | Nature                                     | Dependencies                                                                 | GHC Support          
|----------------------|--------------------------------------------|------------------------------------------------------------------------------|--------------------  
| `libsodium‑bindings` | Low-level FFI bindings                     | `base`                                                                       | Starts with 8.10.7   
| `sel`                | High-level Haskell interface               | `base`, `base16`,  `bytestring`, `text` `text-display`, `libsodium‑bindings` | Starts with 8.10.7 
| `saltine`            | Both FFI bindings and high-level interface | `base`, `bytestring` `deepseq`, `text`, `hashable`, `profunctors`            | Starts with 8.0.2  
| `libsodium`          | Low-level FFI bindings                     | `base`                                                                       | 8.6.5 to 8.10.1    
| `crypto‑sodium`      | High-level Haskell interface               | `base`, `bytestring`, `random`, `cereal`, `libsodium`, `memory`,             | Unclear            

| Name                 | FFI Convention                 | Library Discovery
|----------------------|--------------------------------|-------------------
| `libsodium‑bindings` | Recommended `capi` convention  | `pkg-config`, `homebrew` (macOS-only), cabal‑native
| `saltine`            | Legacy `ccall` convention      | `pkg-config`, cabal-native
| `libsodium`          | Legacy `ccall` convention      | `pkg-config`

[sel]: https://github.com/haskell-cryptography/libsodium-bindings/blob/main/sel/README.md
[sel-badge]: https://github.com/haskell-cryptography/libsodium-bindings/actions/workflows/sel.yml/badge.svg
[sel-ci]: https://github.com/haskell-cryptography/libsodium-bindings/actions/workflows/sel.yml?query=branch%3Amain

[lb]: https://github.com/haskell-cryptography/libsodium-bindings/blob/main/libsodium-bindings/README.md
[lb-badge]: https://github.com/haskell-cryptography/libsodium-bindings/actions/workflows/libsodium-bindings.yml/badge.svg
[lb-ci]: https://github.com/haskell-cryptography/libsodium-bindings/actions/workflows/libsodium-bindings.yml?query=branch%3Amain
