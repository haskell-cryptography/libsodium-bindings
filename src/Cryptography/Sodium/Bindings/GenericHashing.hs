{-# LANGUAGE CApiFFI #-}
{-# LANGUAGE Trustworthy #-}

-- |
--
-- Module: Cryptography.Sodium.Bindings.GenericHashing
-- Description: Direct bindings to the generic hashing primitives of Libsodium.
-- Copyright: (C) Hécate Moonlight 2022
-- License: BSD-3-Clause
-- Maintainer: The Haskell Cryptography Group
-- Stability: Stable
-- Portability: GHC only
module Cryptography.Sodium.Bindings.GenericHashing
  ( -- * Introduction
    -- $introduction

    -- * Operations
    CryptoGenericHashState,
    cryptoGenericHash,
    cryptoGenericHashKeyGen,
    withGenericHashState,
    withGenericHashStateOfSize,
    cryptoGenericHashInit,
    cryptoGenericHashUpdate,
    cryptoGenericHashFinal,

    -- * Constants
    cryptoGenericHashBytes,
    cryptoGenericHashBytesMin,
    cryptoGenericHashBytesMax,
    cryptoGenericHashKeyBytes,
    cryptoGenericHashKeyBytesMin,
    cryptoGenericHashKeyBytesMax,
  )
where

import Foreign (Ptr, allocaBytes)
import Foreign.C (CInt (..), CSize (..), CUChar (..), CULLong (..))

-- $introduction
-- This API computes a fixed-length fingerprint for an arbitrarily long message.
-- It is backed by the BLAKE2b algorithm.
--
-- Sample use cases:
--
--   * File integrity checking
--   * Creating unique identifiers to index arbitrarily long data
--
-- ⚠ Do not use this API module to hash passwords!
--
-- Whenever there is a @'Ptr' 'CryptoGenericHashState'@, it must point to enough memory
-- to hold the hash state.
-- This is at least 'cryptoGenericHashBytesMin', at most
-- 'cryptoGenericHashBytesMax', and should typically be 'cryptoGenericHashBytes'.
-- It is the caller's responsibility to ensure that this holds.

-- | Opaque tag representing the hash state struct @crypto_generichash_state@ used by the C API.
--
-- To use a 'CryptoGenericHashState', use 'withGenericHashState'.
--
-- @since 0.0.1.0
data CryptoGenericHashState

-- | This function allocates a 'CryptoGenericHashState' of size 'cryptoGenericHashBytes'.
-- If you want more control over the size of the hash state, use 'withGenericHashStateOfSize'.
--
-- @since 0.0.1.0
withGenericHashState :: (Ptr CryptoGenericHashState -> IO a) -> IO a
withGenericHashState action = withGenericHashStateOfSize cryptoGenericHashBytes action

-- | This function allocates a 'CryptoGenericHashState' of the desired size.
--
-- Use the following constants as parameter to this function:
--
--   * 'cryptoGenericHashBytesMin' (16U)
--   * 'cryptoGenericHashBytes' (32U)
--   * 'cryptoGenericHashBytesMax' (64U)
--
-- @since 0.0.1.0
withGenericHashStateOfSize :: CSize -> (Ptr CryptoGenericHashState -> IO a) -> IO a
withGenericHashStateOfSize size action = allocaBytes (fromIntegral size) action

-- | Put a fingerprint of the message (the @in@ parameter) of length @inlen@ into
-- the @out@ buffer.
-- The minimum recommended output size (@outlen@) is 'cryptoGenericHashBytes'.
-- However, for specific use cases, the size can be any value between 'cryptoGenericHashBytesMin' (included)
-- and 'cryptoGenericHashBytesMax' (included).
--
-- The @key@ parameter can be NULL and keylen can be 0. In this case, a message will always have the same fingerprint
-- But a key can also be specified. A message will always have the same fingerprint for a given key, but different
-- keys used to hash the same message are very likely to produce distinct fingerprints.
-- In particular, the key can be used to make sure that different applications generate different fingerprints even
-- if they process the same data.
--
-- The recommended key size is 'cryptoGenericHashKeyBytes' bytes.
--
-- However, the key size can be any value between 0 (included) and 'cryptoGenericHashKeyBytesMax' (included).
-- If the key is meant to be secret, the recommended minimum length is 'cryptoGenericHashKeyBytesMin'.
--
-- @since 0.0.1.0
foreign import capi "sodium.h crypto_generichash"
  cryptoGenericHash ::
    -- | @out@ parameter.
    Ptr CUChar ->
    -- | @outlen@ parameter.
    CSize ->
    -- | @in@ parameter.
    Ptr CUChar ->
    -- | @inlen@ parameter.
    CULLong ->
    -- | @key@ parameter.
    Ptr CUChar ->
    -- | @keylen@ parameter.
    CSize ->
    -- | Returns 0 on success, -1 on error.
    IO CInt

-- | Initialise a hash state with a key of a specified length, and
-- produce an output with the specified length in bytes.
--
-- The @'Ptr' 'CUChar'@ argument must point to enough memory to hold a key,
-- which must also be initialised.
-- This is at least 'cryptoGenericHashKeyBytesMin', at most
-- 'cryptoGenericHashKeyBytesMax', and should typically be 'cryptoGenericHashKeyBytes'.
-- It is the caller's responsibility to ensure that these hold.
--
-- @since 0.0.1.0
foreign import capi "sodium.h crypto_generichash_init"
  cryptoGenericHashInit ::
    -- | Pointer to the hash state
    Ptr CryptoGenericHashState ->
    -- | Pointer to a key
    Ptr CUChar ->
    -- | Length of the key
    CSize ->
    -- | Length of the result
    CSize ->
    -- | Returns 0 on success, -1 on error.
    IO CInt

-- | If you process a message in chunks, you can sequentially process each chunk by calling 'cryptoGenericHashUpdate'
-- by providing a pointer to the previously initialised state, a pointer to the input chunk,
-- and the length of the chunk in bytes.
--
-- @since 0.0.1.0
foreign import capi "sodium.h crypto_generichash_update"
  cryptoGenericHashUpdate ::
    -- | Pointer to the hash state
    Ptr CryptoGenericHashState ->
    -- | Pointer to a chunk to be processed
    Ptr CUChar ->
    -- | Length of the chunk in bytes
    CULLong ->
    -- | Returns 0 on success, -1 on error.
    IO CInt

-- | After processing everything you need with 'cryptoGenericHashUpdate', you can finalise the operation
-- with 'cryptoGenericHashFinal'.
--
-- @since 0.0.1.0
foreign import capi "sodium.h crypto_generichash_final"
  cryptoGenericHashFinal ::
    -- | The hash state used throughout the previous hashing operations.
    Ptr CryptoGenericHashState ->
    -- | The pointer to the resulting fingerprint.
    Ptr CUChar ->
    -- | Size of the hash.
    CSize ->
    -- | Returns 0 on success, -1 if called twice.
    IO CInt

-- | This function creates a key of the recommended length 'cryptoGenericHashKeyBytes'.
--
-- @since 0.0.1.0
foreign import capi "sodium.h crypto_generichash_keygen"
  cryptoGenericHashKeyGen ::
    -- | A pointer to the key
    Ptr CUChar ->
    IO ()

-- | Haskell binding to the @crypto_generichash_BYTES@ constant
--
-- @since 0.0.1.0
foreign import capi "sodium.h value crypto_generichash_BYTES"
  cryptoGenericHashBytes :: CSize

-- | Haskell binding to the @crypto_generichash_BYTES_MIN@ constant
--
-- @since 0.0.1.0
foreign import capi "sodium.h value crypto_generichash_BYTES_MIN"
  cryptoGenericHashBytesMin :: CSize

-- | Haskell binding to the @crypto_generichash_BYTES_MAX@ constant
--
-- @since 0.0.1.0
foreign import capi "sodium.h value crypto_generichash_BYTES_MAX"
  cryptoGenericHashBytesMax :: CSize

-- | Haskell binding to the @crypto_generichash_KEYBYTES@ constant
--
-- @since 0.0.1.0
foreign import capi "sodium.h value crypto_generichash_KEYBYTES"
  cryptoGenericHashKeyBytes :: CSize

-- | Haskell binding to the @crypto_generichash_KEYBYTES_MIN@ constant
--
-- @since 0.0.1.0
foreign import capi "sodium.h value crypto_generichash_KEYBYTES_MIN"
  cryptoGenericHashKeyBytesMin :: CSize

-- | Haskell binding to the @crypto_generichash_KEYBYTES_MAX@ constant
--
-- @since 0.0.1.0
foreign import capi "sodium.h value crypto_generichash_KEYBYTES_MAX"
  cryptoGenericHashKeyBytesMax :: CSize
