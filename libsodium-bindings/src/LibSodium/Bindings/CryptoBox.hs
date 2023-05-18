{-# LANGUAGE CApiFFI #-}

-- |
-- Module: LibSodium.Bindings.CryptoBox
-- Description: Direct bindings to the public key authentication primitives backed by X25519 (key exchange), XSalsa20 (encryption) and Poly1305 (authentication)
-- Copyright: (C) Hécate Moonlight
-- License: BSD-3-Clause
-- Maintainer: The Haskell Cryptography Group
-- Stability: Stable
-- Portability: GHC only
module LibSodium.Bindings.CryptoBox
  ( -- ** Introduction
    -- $introduction

    -- ** Usage
    -- $usage

    -- ** Functions

    -- *** Key Pair Generation
    cryptoBoxKeyPair
  , cryptoBoxSeedKeyPair

    -- *** Combined Mode
  , cryptoBoxEasy
  , cryptoBoxOpenEasy

    -- *** Detached Mode
  , cryptoBoxDetached
  , cryptoBoxOpenDetached

    -- *** Precalculation Interface
  , cryptoBoxBeforeNM
  , cryptoBoxEasyAfterNM
  , cryptoBoxOpenEasyAfterNM
  , cryptoBoxDetachedAfterNM
  , cryptoBoxOpenDetachedAfterNM

    -- ** Constants
  , cryptoBoxPublicKeyBytes
  , cryptoBoxSecretKeyBytes
  , cryptoBoxSeedBytes
  , cryptoBoxMacBytes
  , cryptoBoxNonceBytes
  , cryptoBoxBeforeNMBytes
  ) where

import Foreign (Ptr)
import Foreign.C (CInt (CInt), CSize (CSize), CUChar, CULLong (CULLong))

-- $introduction
-- Using public-key authenticated encryption, Alice can encrypt a confidential message specifically for Bob, using Bob's public key.
--
-- Based on Bob's public key, Alice can compute a shared secret key. Using Alice's public key and his secret key, Bob can compute the same shared secret key.
-- That shared secret key can be used to verify that the encrypted message was not tampered with before decryption.
--
-- To send messages to Bob, Alice only needs Bob's public key. Bob should never share his secret key, even with Alice.
--
-- For verification and decryption, Bob only needs Alice's public key, the nonce, and the ciphertext. Alice should never share her secret key either, even with Bob.
--
-- Bob can reply to Alice using the same system without needing to generate a distinct key pair.
--
-- The nonce doesn't have to be confidential, but it should be used with just one invocation of 'cryptoBoxEasy' for a particular pair of public and secret keys.
--
-- One easy way to generate a nonce is to use 'LibSodium.Bindings.Random.randombytesBuf'. Considering the size of the nonce, the risk of a random collision is negligible.
--
-- For some applications, if you wish to use nonces to detect missing messages or to ignore replayed messages, it is also acceptable to use a simple
-- incrementing counter as a nonce.
-- However, you must ensure that the same value is never reused. Be careful as you may have multiple threads or even hosts generating messages using the same key pairs.
-- A better alternative is to use the 'LibSodium.Bindings.SecretStream' API.
--
-- As stated above, senders can decrypt their own messages and compute a valid authentication tag for any messages encrypted with a given shared secret key.
-- This is generally not an issue for online protocols. If this is not acceptable, then check out the Sealed Boxes and Key Exchange sections of the documentation.

-- $usage
-- There are three families of APIs exposed:
--
-- 1. Combined Mode: It is the most commonly used entry point to this module.
-- 2. Detached Mode: If you need to store the authentication tag and encrypted message at different locations
-- 3. Precalculation Interface: Applications that send several messages to the same recipient or receive several messages from the same sender can improve performance by calculating the shared key only once and reusing it in subsequent operations.

-- === Key Pair Generation ===

-- | Generate a random secret key and the corresponding public key.
--
-- /See:/ [crypto_box_keypair()](https://doc.libsodium.org/public-key_cryptography/authenticated_encryption#key-pair-generation)
--
-- @since 0.0.1.0
foreign import capi "sodium.h crypto_box_keypair"
  cryptoBoxKeyPair
    :: Ptr CUChar
    -- ^ Buffer that will hold the public key, of size 'cryptoBoxPublicKeyBytes'
    -> Ptr CUChar
    -- ^ Buffer that will hold the secret key, of size 'cryptoBoxSecretKeyBytes'
    -> IO CInt
    -- ^ The function returns 0 on success and -1 if something fails.

-- | Generate a random secret key and the corresponding public key in a deterministic manner
-- from a single key that acts as a seed.
--
-- /See:/ [crypto_box_seed_keypair()](https://doc.libsodium.org/public-key_cryptography/authenticated_encryption#key-pair-generation)
--
-- @since 0.0.1.0
foreign import capi "sodium.h crypto_box_seed_keypair"
  cryptoBoxSeedKeyPair
    :: Ptr CUChar
    -- ^ Buffer that will hold the public key, of size 'cryptoBoxPublicKeyBytes'
    -> Ptr CUChar
    -- ^ Buffer that will hold the secret key, of size 'cryptoBoxSecretKeyBytes'
    -> Ptr CUChar
    -- ^ Buffer that holds the seed, of size 'cryptoBoxSeedBytes'
    -> IO CInt
    -- ^ The function returns 0 on success and -1 if something fails.

-- === Combined Mode ===

-- | Encrypt a message using the public key of the recipient, the secret key of the sender and a cryptographic nonce.
--
-- The pointers to the buffers containing the message to encrypt and the
-- combination of authentication tag and encrypted message can overlap, making in-place
-- encryption possible. However do not forget that 'cryptoBoxMacBytes' extra bytes are required to prepend the tag.
--
-- /See:/ [crypto_box_easy()](https://doc.libsodium.org/public-key_cryptography/authenticated_encryption#combined-mode)
--
-- @since 0.0.1.0
foreign import capi "crypto_box_easy"
  cryptoBoxEasy
    :: Ptr CUChar
    -- ^ Buffer that will hold the authentication tag, of size 'cryptoBoxMacBytes' + @messageLength@
    -> Ptr CUChar
    -- ^ Buffer that holds the message to be encrypted
    -> CULLong
    -- ^ Length of the message in bytes (@messageLength@)
    -> Ptr CUChar
    -- ^ Nonce, that should be of size 'cryptoBoxNonceBytes'
    -> Ptr CUChar
    -- ^ Buffer that holds the public key, of size 'cryptoBoxPublicKeyBytes'
    -> Ptr CUChar
    -- ^ Buffer that holds the secret key, of size 'cryptoBoxSecretKeyBytes'
    -> IO CInt
    -- ^ The function returns 0 on success and -1 if something fails.

-- | Verify and decrypt a cyphertext produced by 'cryptoBoxEasy'.
-- The first argument is a pointer to a combination of authentication tag and message
-- as produced by 'cryptoBoxEasy'.
--
-- The pointers to the buffers containing the plaintext message and the
-- combination of authentication tag and encrypted message can overlap, making in-place
-- decryption possible.
--
-- /See:/ [crypto_box_open_easy()](https://doc.libsodium.org/public-key_cryptography/authenticated_encryption#combined-mode)
--
-- @since 0.0.1.0
foreign import capi "crypto_box_open_easy"
  cryptoBoxOpenEasy
    :: Ptr CUChar
    -- ^ Buffer that will hold the decrypted message
    -> Ptr CUChar
    -- ^ Buffer that holds the authentication tag and encrypted message combination produced by 'cryptoBoxEasy'.
    -> CULLong
    -- ^ Length of the authentication tag and encrypted message combination, which is 'cryptoBoxMacBytes' + length of the message
    -> Ptr CUChar
    -- ^ Nonce, that should be at least of size 'cryptoBoxNonceBytes'. It must match the nonce used by 'cryptoBoxEasy'.
    -> Ptr CUChar
    -- ^ Buffer that holds the public key, of size 'cryptoBoxPublicKeyBytes'
    -> Ptr CUChar
    -- ^ Buffer that holds the secret key, of size 'cryptoBoxSecretKeyBytes'
    -> IO CInt
    -- ^ The function returns -1 if the verification fails and 0 on success

-- | Encrypt a message in the same way as 'cryptoBoxEasy' with the
-- the authentication tag and the encrypted message held in separate buffers.
--
-- /See:/ [crypto_box_detached()](https://doc.libsodium.org/public-key_cryptography/authenticated_encryption#detached-mode)
--
-- @since 0.0.1.0
foreign import capi "crypto_box_detached"
  cryptoBoxDetached
    :: Ptr CUChar
    -- ^ Buffer that will hold the encrypted message.
    -> Ptr CUChar
    -- ^ Buffer that will hold the authentication tag, of size 'cryptoBoxMacBytes'
    -> Ptr CUChar
    -- ^ Buffer that holds the message to be encrypted.
    -> CULLong
    -- ^ Length of the message to be encrypted.
    -> Ptr CUChar
    -- ^ Nonce, that should be of size 'cryptoBoxNonceBytes'.
    -- It must match the nonce used by 'cryptoBoxEasy'.
    -> Ptr CUChar
    -- ^ Buffer that holds the public key, of size 'cryptoBoxPublicKeyBytes'
    -> Ptr CUChar
    -- ^ Buffer that holds the secret key, of size 'cryptoBoxSecretKeyBytes'
    -> IO CInt
    -- ^ The function returns -1 if the verification fails and 0 on success

-- | Decrypt a message in the same way as 'cryptoBoxEasy' with the
-- the authentication tag and the encrypted message held in separate buffers.
--
-- /See:/ [crypto_box_open_detached()](https://doc.libsodium.org/public-key_cryptography/authenticated_encryption#detached-mode)
--
-- @since 0.0.1.0
foreign import capi "crypto_box_open_detached"
  cryptoBoxOpenDetached
    :: Ptr CUChar
    -- ^ Buffer that will hold the plaintext message
    -> Ptr CUChar
    -- ^ Buffer that holds the encrypted message
    -> Ptr CUChar
    -- ^ Buffer that will hold the authentication tag, of size 'cryptoBoxMacBytes'
    -> CULLong
    -- ^ Length of the plaintext message
    -> Ptr CUChar
    -- ^ Nonce, that should be at least of size 'cryptoBoxNonceBytes'.
    -> Ptr CUChar
    -- ^ Buffer that holds the public key, of size 'cryptoBoxPublicKeyBytes'
    -> Ptr CUChar
    -- ^ Buffer that holds the secret key, of size 'cryptoBoxSecretKeyBytes'
    -> IO CInt
    -- ^ The function returns -1 if the verification fails and 0 on success

-- | Compute a shared secret key of size 'cryptoBoxBeforeNMBytes'
-- given a public key and a secret key.
--
-- /See:/ [crypto_box_beforenm()](https://doc.libsodium.org/public-key_cryptography/authenticated_encryption#precalculation-interface)
--
-- @since 0.0.1.0
foreign import capi "crypto_box_beforenm"
  cryptoBoxBeforeNM
    :: Ptr CUChar
    -- ^ Buffer that will hold the newly-generated shared secret key, of size 'cryptoBoxBeforeNMBytes'
    -> Ptr CUChar
    -- ^ Buffer that holds the public key, of size 'cryptoBoxPublicKeyBytes'
    -> Ptr CUChar
    -- ^ Buffer that holds the secret key, of size 'cryptoBoxSecretKeyBytes'
    -> IO CInt
    -- ^ The function returns 0 on success and -1 if something fails.

-- | Encrypt a message using the public key of the recipient, a cryptographic nonce and a shared secret key.
--
-- /See:/ [crypto_box_easy_afternm()](https://doc.libsodium.org/public-key_cryptography/authenticated_encryption#precalculation-interface)
--
-- @since 0.0.1.0
foreign import capi "crypto_box_easy_afternm"
  cryptoBoxEasyAfterNM
    :: Ptr CUChar
    -- ^ Buffer that will holds the encrypted message.
    -> Ptr CUChar
    -- ^ Buffer that holds the plaintext message.
    -> CULLong
    -- ^ Length of the plaintext message
    -> Ptr CUChar
    -- ^ Nonce, that should of size 'cryptoBoxNonceBytes'.
    -> Ptr CUChar
    -- ^ Precalculated shared secret key (created by 'cryptoBoxBeforeNM').
    -> IO CInt
    -- ^ The function returns -1 if the verification fails and 0 on success

-- | Decrypt a message using the public key of the recipient, a cryptographic nonce and a shared secret key.
--
-- /See:/ [crypto_box_open_easy_afternm()](https://doc.libsodium.org/public-key_cryptography/authenticated_encryption#precalculation-interface)
--
-- @since 0.0.1.0
foreign import capi "crypto_box_open_easy_afternm"
  cryptoBoxOpenEasyAfterNM
    :: Ptr CUChar
    -- ^ Buffer that will hold the decrypted plaintext message.
    -> Ptr CUChar
    -- ^ Buffer that holds the encrypted message.
    -> CULLong
    -- ^ Length of the plaintext message
    -> Ptr CUChar
    -- ^ Nonce, that should be at least of size 'cryptoBoxNonceBytes'.
    -> Ptr CUChar
    -- ^ Precalculated shared secret key (created by 'cryptoBoxBeforeNM').
    -> IO CInt
    -- ^ The function returns -1 if the verification fails and 0 on success

-- | Encrypt a message in the same way as 'cryptoBoxDetached' with the
-- the authentication tag and the encrypted message held in separate buffers, with the difference
-- that a precalculated, shared secret key is used instead of a public/secret key pair.
--
-- /See:/ [crypto_box_detached_afternm()](https://doc.libsodium.org/public-key_cryptography/authenticated_encryption#precalculation-interface)
--
-- @since 0.0.1.0
foreign import capi "crypto_box_detached_afternm"
  cryptoBoxDetachedAfterNM
    :: Ptr CUChar
    -- ^ Buffer that will hold the encrypted message.
    -> Ptr CUChar
    -- ^ Buffer that will hold the authentication tag, of size 'cryptoBoxMacBytes'
    -> Ptr CUChar
    -- ^ Buffer that holds the plaintext message.
    -> CULLong
    -- ^ Length of the plaintext message
    -> Ptr CUChar
    -- ^ Nonce, that should be at least of size 'cryptoBoxNonceBytes'.
    -> Ptr CUChar
    -- ^ Precalculated shared secret key (created by 'cryptoBoxBeforeNM').
    -> IO CInt
    -- ^ The function returns -1 if the verification fails and 0 on success

-- | Decrypt a message using the public key of the recipient, a cryptographic nonce and a shared secret key.
--
-- /See:/ [crypto_box_open_detached_afternm()](https://doc.libsodium.org/public-key_cryptography/authenticated_encryption#precalculation-interface)
--
-- @since 0.0.1.0
foreign import capi "crypto_box_open_detached_afternm"
  cryptoBoxOpenDetachedAfterNM
    :: Ptr CUChar
    -- ^ Buffer that will hold the decrypted plaintext message.
    -> Ptr CUChar
    -- ^ Buffer that holds the encrypted message.
    -> Ptr CUChar
    -- ^ Buffer that holds the authentication tag, of size 'cryptoBoxMacBytes'
    -> CULLong
    -- ^ Length of the plaintext message
    -> Ptr CUChar
    -- ^ Nonce, that should be at least of size 'cryptoBoxNonceBytes'.
    -> Ptr CUChar
    -- ^ Precalculated shared secret key (created by 'cryptoBoxBeforeNM').
    -> IO CInt
    -- ^ The function returns -1 if the verification fails and 0 on success

-- === Constants

-- |
--
-- /See:/ [crypto_box_PUBLICKEYBYTES](https://doc.libsodium.org/public-key_cryptography/authenticated_encryption#constants)
--
-- @since 0.0.1.0
foreign import capi "sodium.h value crypto_box_PUBLICKEYBYTES"
  cryptoBoxPublicKeyBytes :: CSize

-- |
--
-- /See:/ [crypto_box_SECRETKEYBYTES](https://doc.libsodium.org/public-key_cryptography/authenticated_encryption#constants)
--
-- @since 0.0.1.0
foreign import capi "sodium.h value crypto_box_SECRETKEYBYTES"
  cryptoBoxSecretKeyBytes :: CSize

-- |
--
-- /See:/ [crypto_box_SEEDBYTES](https://doc.libsodium.org/public-key_cryptography/authenticated_encryption#constants)
--
-- @since 0.0.1.0
foreign import capi "sodium.h value crypto_box_SEEDBYTES"
  cryptoBoxSeedBytes :: CSize

-- |
--
-- /See:/ [crypto_box_MACBYTES](https://doc.libsodium.org/public-key_cryptography/authenticated_encryption#constants)
--
-- @since 0.0.1.0
foreign import capi "sodium.h value crypto_box_MACBYTES"
  cryptoBoxMacBytes :: CSize

-- |
--
-- /See:/ [crypto_box_NONCEBYTES](https://doc.libsodium.org/public-key_cryptography/authenticated_encryption#constants)
--
-- @since 0.0.1.0
foreign import capi "sodium.h value crypto_box_NONCEBYTES"
  cryptoBoxNonceBytes :: CSize

-- |
--
-- /See:/ [crypto_box_BEFORENMBYTES](https://doc.libsodium.org/public-key_cryptography/authenticated_encryption#constants)
--
-- @since 0.0.1.0
foreign import capi "sodium.h value crypto_box_BEFORENMBYTES"
  cryptoBoxBeforeNMBytes :: CSize
