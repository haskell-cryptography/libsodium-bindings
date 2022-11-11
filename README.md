# libsodium-bindings [![CI](https://github.com/haskell-cryptography/libsodium-bindings/actions/workflows/ci.yml/badge.svg)](https://github.com/haskell-cryptography/libsodium-bindings/actions/workflows/ci.yml) [![made with Haskell](https://img.shields.io/badge/Made%20in-Haskell-%235e5086?logo=haskell&style=flat-square)](https://haskell.org)

`libsodium-bindings` exposes a set of FFI bindings from the `libsodium-1.0.18-stable` library.

Here are the principles of the library (from our [STRUCTURE](https://github.com/haskell-cryptography/governance/blob/main/STRUCTURE.md) document):

  * Users of this library should never have to even think about how the libraries are bundled or linked to.
  * This library does not have any dependencies other than base. 
  * The documentation for the modules must be strong enough to stand alone.
  * CI checks that the wrapping or bundling works correctly. This includes checks on Windows.

## Comparison with other libraries

These other libraries available in Hackage provide bindings to libsodium. Here are how they differ from libsodium-bindings:

### [saltine](https://hackage.haskell.org/package/saltine)

`saltine` is a library maintained by Max Amanshauser.  

The library dynamically links to the system's libsodium 1.0.18 through pkg-config and depends on 
several non-`base` packages like `bytestring`, `deepseq`, `hashable`, `profunctors` and `text-1.2`.  
It supports GHC from 8.0.2 to 9.0.1.
`saltine` combines both FFI bindings and Haskell utilities, and uses the `ccall` FFI calling convention convention.
Its documentation meets our quality standards

In comparison, `libsodium-bindings` statically links to libsodium 1.0.18-stable, and does not depend on non-`base` packages.
In particular, since there is no dependency on `text`, you are free to use `text-2.0` or stay on the 1.2 branch.
`libsodium-bindings` only provides FFI bindings, and can be used as a dependency by higher-level interfaces.
It supports GHC from 8.10.7 to 9.2.1.
Moreover, it follows the latest
[GHC recommendations regarding foreign imports](https://www.haskell.org/ghc/blog/20210709-capi-usage.html#recommendations),
and uses the `capi` calling convention.

### [Libsodium](https://hackage.haskell.org/package/libsodium)

`libsodium` is  a library maintained by Renzo Carbonara.  

The library dynamically links to the system's libsodium 1.0.18 through pkg-config and does not depend on non-`base` packages.
It requires c2hs to be installed on the developer's system, and supports GHC from 8.6.5 to 8.10.1
`libsodium` only provides FFI bindings, and uses the `ccall` FFI calling convention.  
Documentation is lacking from the project, and requires a back-and-forth between the package and the libsodium documentation.

In comparison, `libsodium-bindings` statically links to libsodium 1.0.18, and does not use `c2hs`.
It supports GHC from 8.10.7 to 9.2.1.
`libsodium-bindings` uses the `capi` FFI calling convention.  
The documentation of the project aims to render the user self-sufficient.
