-- |
--
-- Module: LibSodium.Bindings
-- Description: Index of the libsodium-bindings package
-- Copyright: (C) Hécate Moonlight 2023
-- License: BSD-3-Clause
-- Maintainer: The Haskell Cryptography Group
-- Stability: Stable
-- Portability: GHC only
module LibSodium.Bindings
  ( -- * Index

    -- ** Secret-key Cryptography

    -- *** Authenticated Encryption

    -- | Encrypt a message and compute an authentication tag to make sure the message hasn't been tampered with.
    --
    -- Module: [SecretBox]("LibSodium.Bindings.Secretbox")
    --
    -- Uses:
    --
    --    * Encryption: XSalsa20 stream cipher
    --    * Authentication: Poly1305 MAC

    -- *** Encrypted Streams

    -- | Encrypt a sequence of messages, or a single message split into an arbitrary number of chunks, using a secret key.
    --
    -- Module: [SecretStream]("LibSodium.Bindings.SecretStream")
    --
    -- Uses:
    --
    --    * Initialisation: XChaCha20
    --    * Encryption: ChaCha20Poly1305-IETF

    -- *** Authentication

    -- | Compute an authentication tag for a message and a secret key, and verify that a given tag is valid for a given message and a key.
    --
    -- Module: [CryptoAuth]("LibSodium.Bindings.CryptoAuth")
    --
    -- Uses:
    --
    --     * Authentication: HMAC-SHA512-256

    -- ** Public-key Cryptography

    -- *** Authenticated Encryption

    -- | Encrypt a confidential message with the recipient's public key, who can then decrypt it with their secret key.
    --
    -- Module: [CryptoBox]("LibSodium.Bindings.CryptoBox")
    --
    -- Uses:
    --
    --     * Key exchange: X25519
    --     * Encryption: XSalsa20
    --     * Authentication: Poly1305

    -- *** Public-key Signatures

    -- | Sign messages with a secret key, and distribute a public key, which anybody can use to verify that the signature appended
    -- to a message was issued by the creator of the public key.
    --
    -- Module: [CryptoSign]("LibSodium.Bindings.CryptoSign")
    --
    -- Uses:
    --
    --    * Single-part signature: Ed25519
    --    * Multi-part signature: Ed25519ph

    -- *** Sealed Boxes

    -- | Anonymously send messages to a recipient given their public key.
    --
    -- Module: [SealedBoxes]("LibSodium.Bindings.SealedBoxes")
    --
    -- Uses:
    --
    --    * Key Exchange: X25519
    --    * Encryption: XSalsa20-Poly1305.

    -- ** Hashing

    -- *** Generic Hashing

    -- | Computes a fixed-length fingerprint for an arbitrarily long message.
    --
    -- Use this for file integrity checking and create unique identifiers to index arbitrarily long data.
    --
    -- ⚠️ Do not use this API to hash passwords!
    --
    -- Module: [GenericHashing]("LibSodium.Bindings.GenericHashing")
    --
    -- Uses:
    --
    --    * Hashing: BLAKE2b

    -- *** Short-input Hashing

    -- | Produce short hashes for your data, suitable to build Hash tables, probabilistic data structures or perform integrity checking in interactive protocols.
    --
    -- Module: [ShortHashing]("LibSodium.Bindings.ShortHashing")
    --
    -- Uses:
    --
    --    * Hashing: SipHash-2-4

    -- *** Password Hashing

    -- | Hash passwords with high control on the computation parameters.
    --
    -- Module: [PasswordHashing]("LibSodium.Bindings.PasswordHashing")
    --
    -- Uses:
    --
    --    * Hashing: Argon2id v1.3

    -- ** Key Derivation

    -- | Derive secret keys from a single high-entropy key.
    --
    -- Module: [KeyDerivation]("LibSodium.Bindings.KeyDerivation")
    --
    -- Uses:
    --
    --    * Key derivation: BLAKE2B

    -- ** Key Exchange

    -- | Securely compute a set of shared keys using your peer's public key and your own secret key.
    --
    -- Module: [KeyExchange]("LibSodium.Bindings.KeyExchange")
    --
    -- Uses:
    --
    --    * Key generation: BLAKE2B-512

    -- ** Generating Random Data

    -- | Generate unpredictable data, suitable for creating secret keys.
    --
    -- Module: [Random]("LibSodium.Bindings.Random")
    --
    -- Uses:
    --
    --    * Windows: @RtlGenRandom()@
    --    * OpenBSD & Bitrig: @arc4random()@
    --    * FreeBSD & Linux: @getrandom()@
    --    * Other UNIX systems: @\/dev\/urandom@

    -- ** Secure Memory

    -- | Allocate, lock, overwrite and guard heap allocations in your memory for sensitive operations.
    --
    -- Module: [SecureMemory]("LibSodium.Bindings.SecureMemory")
    --
    -- Locking uses:
    --
    --    * Windows: @VirtualLock()@
    --    * UNIX systems: @mlock()@

    -- ** Other cryptography constructs

    -- *** SHA2

  --

    -- | Provide compatibility with existing applications for SHA-256 and SHA-512.
    --
    -- You should prioritise [GenericHashing]("LibSodium.Bindings.GenericHashing") and
    -- [PasswordHashing]("LibSodium.Bindings.PasswordHashing") for new development instead.
    --
    -- Module: [SHA2]("LibSodium.Bindings.SHA2")

    -- *** AEAD

  --

    -- | Encrypt a message with a key and a nonce to keep it confidential, compute an authentication tag, and store optional, non-confidential data.
    --
    -- Module: [AEAD]("LibSodium.Bindings.AEAD")
    --
    -- Uses:
    --
    --    * Encryption: XChaCha20 stream cipher
    --    * Authentication: Poly1305 MAC

    -- *** XChaCha20

    -- | Implementation of the XChaCha20 stream cipher
    --
    -- Module: [XChaCha20]("LibSodium.Bindings.XChaCha20")
  ) where
