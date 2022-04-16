{-# LANGUAGE CApiFFI #-}
{-# LANGUAGE Trustworthy #-}

-- |
--
-- Module: Cryptography.Sodium.Bindings.SHA512
-- Description: Direct bindings to the SHA-512 hashing function implemented in Libsodium
-- Copyright: (C) Hécate Moonlight 2022
-- License: BSD-3-Clause
-- Maintainer: The Haskell Cryptography Group
-- Stability: Stable
-- Portability: GHC only
module Cryptography.Sodium.Bindings.SHA512
  ( -- * Introduction
    -- $introduction

    -- * Single-part message
    cryptoHashSHA512,

    -- * Multi-part messages
    CryptoHashSHA512State (..),
    cryptoHashSHA512Init,
    cryptoHashSHA512Update,
    cryptoHashSHA512Final,
    -- * Constants
    cryptoHashSHA512Bytes,
  )
where

import Foreign (Ptr)
import Foreign.C (CInt (..), CSize (..), CUChar (..), CULLong (..))

-- $introduction
--
-- The SHA-512 functions are provided for interoperability with other applications. If you are
-- looking for a generic hash function and not specifically SHA-2, using
-- 'Cryptography.Sodium.Bindings.GenericHashing' (BLAKE2b) might be a better choice.
-- These functions are also not suitable for hashing passwords or deriving keys from passwords.
-- Use 'Cryptography.Sodium.Bindings.PasswordHashing' instead.
--
-- These functions are not keyed and are thus deterministic. In addition, the untruncated versions
-- are vulnerable to length extension attacks. A message can be hashed in a single pass, but a
-- streaming API is also available to process a message as a sequence of multiple chunks.


-- | Hash the content of the second buffer and put the result in the first buffer.
--
-- @since 0.0.1.0
foreign import capi "sodium.h crypto_hash_sha512"
  cryptoHashSHA512 ::
    -- | A pointer to the hash of your data.
    Ptr CUChar ->
    -- | A pointer to the data you want to hash.
    Ptr CUChar ->
    -- | The length of the data you want to hash.
    CULLong ->
    -- | Return code is 0 on success, -1 on error.
    IO CInt

-- | This is the opaque state held and used by the various functions of this
-- module.
--
-- @since 0.0.1.0
data CryptoHashSHA512State = CryptoHashSHA512State

-- | This function initializes the 'CryptoHashSHA512State' state.
--
-- It must be called before the first 'cryptoHashSHA512Update' call.
--
-- @since 0.0.1.0
foreign import capi "sodium.h crypto_hash_sha512_init"
  cryptoHashSHA512Init ::
    -- | A pointer to the 'CryptoHashSHA512State'. Cannot be 'Foreign.nullPtr'.
    Ptr CryptoHashSHA512State ->
    -- | Return code is 0 on success, -1 on error.
    IO CInt

-- | Add a new chunk to the message that will eventually be hashed.
--
-- After all parts have been supplied, 'cryptoHashSHA512Final' can be used to finalise the operation
-- and get the final hash.
--
-- @since 0.0.1.0
foreign import capi "sodium.h crypto_hash_sha512_update"
  cryptoHashSHA512Update ::
    -- | A pointer to the 'CryptoHashSHA512State'. Cannot be 'Foreign.nullPtr'.
    Ptr CryptoHashSHA512State ->
    -- | A pointer to the new message chunk to process.
    Ptr CUChar ->
    -- | The length in bytes of the chunk.
    CULLong ->
    -- | Return code is 0 on success, -1 on error.
    IO CInt

-- | Finalise the hashing of a message. The final hash is padded with extra zeros if necessary,
-- then put in a buffer.
--
-- After this operation, the buffer containing the 'CryptoHashSHA512State' is emptied and
-- cannot be relied upon.
--
-- @since 0.0.1.0
foreign import capi "sodium.h crypto_hash_sha512_final"
  cryptoHashSHA512Final ::
    -- | A pointer to the 'CryptoHashSHA512State'. Cannot be 'Foreign.nullPtr'.
    Ptr CryptoHashSHA512State ->
    -- | The buffer in which the final hash is stored.
    Ptr CUChar ->
    -- | Return code is 0 on success, -1 on error.
    IO CInt

-- | This constant represents the size of a pre-hashed message.
-- It is in use in the @ED25519ph@ multi-part signing system.
--
-- For more information, please consult the documentation of
-- "Cryptography.Sodium.Bindings.Signing".
--
-- @since 0.0.1.0
foreign import capi "sodium.h value crypto_hash_sha512_BYTES"
  cryptoHashSHA512Bytes :: CSize
