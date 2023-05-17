{-# LANGUAGE CApiFFI #-}

-- |
-- Module: LibSodium.Bindings.KeyDerivation
-- Description: Direct bindings to the key exchange functions implemented in Libsodium. The algorithm used is blake2b.
-- Copyright: (C) Hécate Moonlight 2022
-- License: BSD-3-Clause
-- Maintainer: The Haskell Cryptography Group
-- Stability: Stable
-- Portability: GHC only
module LibSodium.Bindings.KeyDerivation
  ( -- * Introduction
    -- $introduction

    -- ** Key Generation
    cryptoKDFKeygen
  , cryptoKDFDeriveFromKey

    -- ** Constants
  , cryptoKDFBytesMin
  , cryptoKDFBytesMax
  , cryptoKDFKeyBytes
  , cryptoKDFContextBytes
  )
where

import Foreign (Ptr, Word64, Word8)
import Foreign.C (CChar, CInt (CInt), CSize (CSize), CUChar)

-- $introduction
--
-- From a single, high-entropy key, you can derive multiple secret sub-keys.
--
-- This API can derive up to 2⁶⁴ keys from a single key and context, and these
-- sub-keys can have an arbitrary length between 128 (16 bytes) and 512 bits (64 bytes).

-- | Generate a high-entropy key from which the sub-keys will be derived.
--
-- @since 0.0.1.0
foreign import capi "sodium.h crypto_kdf_keygen"
  cryptoKDFKeygen
    :: Ptr Word8
    -- ^ Pointer that will hold the master key of length 'cryptoKDFKeyBytes'
    -> IO ()

-- | Derive a sub-key from a high-entropy secre key with a unique identifier.
-- The identifier can be any value up to 2⁶⁴-1
--
-- @since 0.0.1.0
foreign import capi "sodium.h crypto_kdf_derive_from_key"
  cryptoKDFDeriveFromKey
    :: Ptr CUChar
    -- ^ Pointer that will hold the sub-key.
    -> CSize
    -- ^ Length of the sub-key.
    -> Word64
    -- ^ Identifier of the sub-key. Must not be reused for another sub-key.
    -> Ptr CChar
    -- ^ Pointer to the context, of size 'cryptoKDFContextBytes'.
    -> Ptr CUChar
    -- ^ Pointer to the master key, which will be of length 'cryptoKDFKeyBytes'.
    -> IO CInt
    -- ^ Returns 0 on success and -1 on error.

-- == Constants

-- | Minimum length of a sub-key.
--
-- @since 0.0.1.0
foreign import capi "sodium.h value crypto_kdf_BYTES_MIN"
  cryptoKDFBytesMin :: CSize

-- | Maximum length of a sub-key.
--
-- @since 0.0.1.0
foreign import capi "sodium.h value crypto_kdf_BYTES_MAX"
  cryptoKDFBytesMax :: CSize

-- | Length of a Context.
--
-- @since 0.0.1.0
foreign import capi "sodium.h value crypto_kdf_CONTEXTBYTES"
  cryptoKDFContextBytes :: CSize

-- | Length of the master key.
--
-- @since 0.0.1.0
foreign import capi "sodium.h value crypto_kdf_KEYBYTES"
  cryptoKDFKeyBytes :: CSize
