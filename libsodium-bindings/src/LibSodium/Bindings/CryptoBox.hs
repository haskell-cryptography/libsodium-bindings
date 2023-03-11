{-# LANGUAGE CApiFFI #-}
{-# LANGUAGE ScopedTypeVariables #-}

-- |
-- Module: LibSodium.Bindings.CryptoBox
-- Description: Direct bindings to the public key authentication primitives backed by X25519 (key exchange), XSalsa20 (encryption) and Poly1305 (authentication)
-- Copyright: (C) Hécate Moonlight
-- License: BSD-3-Clause
-- Maintainer: The Haskell Cryptography Group
-- Stability: Stable
-- Portability: GHC only
module LibSodium.Bindings.CryptoBox
  ( -- * Introduction
    -- $introduction

    -- * Usage
    -- $usage

    -- * Functions

    -- ** Key Pair Generation
    cryptoBoxKeyPair
  , cryptoBoxSeedKeyPair

    -- ** Combined Mode
  , cryptoBoxEasy
  , cryptoBoxOpenEasy

    -- ** Detached Mode
  , cryptoBoxDetached
  , cryptoBoxOpenDetached

    -- ** Precalculation Interface
  , cryptoBoxBeforeNM
  , cryptoBoxEasyAfterNM
  , cryptoBoxOpenEasyAfterNM
  , cryptoBoxDetachedAfterNM
  , cryptoBoxOpenDetachedAfterNM

    -- * Constants
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
-- TODO: Write the purpose of public-key authenticated encryption

-- $usage
--
--
-- If you need to store the authentication tag and the encrypted message in different
-- places, do use the "Detached Mode" API.

-- === Key Pair Generation ===

-- | Generate a random secret key and the corresponding public key.
--
-- /See:/ [crypto_box_keypair](https://doc.libsodium.org/public-key_cryptography/authenticated_encryption#key-pair-generation)
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
-- /See:/ [crypto_box_seed_keypair](https://doc.libsodium.org/public-key_cryptography/authenticated_encryption#key-pair-generation)
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
-- encryption possible. However do not forget that 'cryptoBoxMacbytes' extra bytes are required to prepend the tag.
--
-- /See:/ [crypto_box_easy](https://doc.libsodium.org/public-key_cryptography/authenticated_encryption#combined-mode)
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
-- /See:/ [crypto_box_open_easy](https://doc.libsodium.org/public-key_cryptography/authenticated_encryption#combined-mode)
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
-- /See:/ [crypto_box_detached](https://doc.libsodium.org/public-key_cryptography/authenticated_encryption#detached-mode)
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
-- /See:/ [crypto_box_open_detached](https://doc.libsodium.org/public-key_cryptography/authenticated_encryption#detached-mode)
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
-- /See:/ [crypto_box_beforenm](https://doc.libsodium.org/public-key_cryptography/authenticated_encryption#precalculation-interface)
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
-- /See:/ [crypto_box_easy_afternm](https://doc.libsodium.org/public-key_cryptography/authenticated_encryption#precalculation-interface)
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
-- /See:/ [crypto_box_open_easy_afternm](https://doc.libsodium.org/public-key_cryptography/authenticated_encryption#precalculation-interface)
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
-- /See:/ [crypto_box_open_easy_afternm](https://doc.libsodium.org/public-key_cryptography/authenticated_encryption#precalculation-interface)
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
-- /See:/ [crypto_box_open_easy_afternm](https://doc.libsodium.org/public-key_cryptography/authenticated_encryption#precalculation-interface)
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
--  @since 0.0.1.0
foreign import capi "sodium.h value crypto_box_PUBLICKEYBYTES"
  cryptoBoxPublicKeyBytes :: CSize

-- |
-- @since 0.0.1.0
foreign import capi "sodium.h value crypto_box_SECRETKEYBYTES"
  cryptoBoxSecretKeyBytes :: CSize

-- |
-- @since 0.0.1.0
foreign import capi "sodium.h value crypto_box_SEEDBYTES"
  cryptoBoxSeedBytes :: CSize

-- |
-- @since 0.0.1.0
foreign import capi "sodium.h value crypto_box_MACBYTES"
  cryptoBoxMacBytes :: CSize

-- |
-- @since 0.0.1.0
foreign import capi "sodium.h value crypto_box_NONCEBYTES"
  cryptoBoxNonceBytes :: CSize

-- |
-- @since 0.0.1.0
foreign import capi "sodium.h value crypto_box_BEFORENMBYTES"
  cryptoBoxBeforeNMBytes :: CSize
