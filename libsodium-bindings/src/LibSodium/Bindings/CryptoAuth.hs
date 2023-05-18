{-# LANGUAGE CApiFFI #-}
{-# LANGUAGE ScopedTypeVariables #-}

-- |
-- Module: LibSodium.Bindings.CryptoAuth
-- Description: Direct bindings to the secret key authentication primitives backed by HMAC-SHA512-256
-- Copyright: (C) Hécate Moonlight
-- License: BSD-3-Clause
-- Maintainer: The Haskell Cryptography Group
-- Stability: Stable
-- Portability: GHC only
module LibSodium.Bindings.CryptoAuth
  ( -- * Introduction
    -- $introduction

    -- * Usage
    -- $usage

    -- * Functions
    cryptoAuth
  , cryptoAuthVerify
  , cryptoAuthKeygen

    -- * Constants
  , cryptoAuthKeyBytes
  , cryptoAuthBytes
  ) where

import Foreign
import Foreign.C

-- $introduction
-- Compute an authentication tag for a message and a secret key,
-- and verify that a given tag is valid for a given message and a key.
--
-- The function computing the tag is deterministic: the same (message, key)
-- tuple will always produce the same output.
-- However, even if the message is public, knowing the key is required in order to be
-- able to compute a valid tag.
-- Therefore, the key __should remain confidential__. The tag, however, can be public.
--
-- The operations of this module are backed by the HMAC-SHA512-256 algorithm.

-- $usage
--
-- A typical use case is:
--
-- * @A@ prepares a message, adds an authentication tag, sends it to @B@
-- * @A@ doesn't store the message
-- * Later on, @B@ sends the message and the authentication tag to @A@
-- * @A@ uses the authentication tag to verify that it created this message.
--
-- This operation does not encrypt the message.
-- It only computes and verifies an authentication tag.

-- | Compute a tag for the provided message and key.
--
-- /See:/ [crypto_auth()](https://doc.libsodium.org/secret-key_cryptography/secret-key_authentication#usage)
--
-- @since 0.0.1.0
foreign import capi "sodium.h crypto_auth"
  cryptoAuth
    :: Ptr CUChar
    -- ^ Buffer that will hold the computed authenticated tag, of size 'cryptoAuthBytes'
    -> Ptr CUChar
    -- ^ Buffer that holds the input message
    -> CULLong
    -- ^ Length of the message
    -> Ptr CUChar
    -- ^ Buffer that holds the secret key of size 'cryptoAuthKeyBytes'
    -> IO CInt

-- | Verify that the tag is valid for the provided message and secret key.
--
-- /See:/ [crypto_auth_verify()](https://doc.libsodium.org/secret-key_cryptography/secret-key_authentication#usage)
--
-- @since 0.0.1.0
foreign import capi "sodium.h crypto_auth_verify"
  cryptoAuthVerify
    :: Ptr CUChar
    -- ^ Buffer that holds the tag
    -> Ptr CUChar
    -- ^ Buffer that holds the message
    -> CULLong
    -- ^ Length of the message
    -> Ptr CUChar
    -- ^ Buffer that holds the secret key of size 'cryptoAuthKeyBytes'
    -> IO CInt
    -- ^ Returns -1 if the verification fails, and 0 if it passes.

-- | Create a random secret key of size 'cryptoAuthKeyBytes'
--
-- It is equivalent to calling 'LibSodium.Bindings.Random.randombytesBuf' but
-- improves code clarity and can prevent misuse by ensuring that the provided
-- key length is always be correct.
--
-- /See:/ [crypto_auth_keygen()](https://doc.libsodium.org/secret-key_cryptography/secret-key_authentication#usage)
--
-- @since 0.0.1.0
foreign import capi "sodium.h crypto_auth_keygen"
  cryptoAuthKeygen
    :: Ptr CUChar
    -- ^ Buffer that holds the secret key of size 'cryptoAuthKeyBytes'
    -> IO ()

-- === Constants ===

-- | Size of the secret key
--
-- /See:/ [crypto_auth_KEYBYTES](https://doc.libsodium.org/secret-key_cryptography/secret-key_authentication#constants)
--
-- @since 0.0.1.0
foreign import capi "sodium.h value crypto_auth_KEYBYTES"
  cryptoAuthKeyBytes :: CSize

-- | Size of the tag
--
-- /See:/ [crypto_auth_BYTES](https://doc.libsodium.org/secret-key_cryptography/secret-key_authentication#constants)
--
-- @since 0.0.1.0
foreign import capi "sodium.h value crypto_auth_BYTES"
  cryptoAuthBytes :: CSize
