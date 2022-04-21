{-# LANGUAGE CApiFFI #-}
{-# LANGUAGE Trustworthy #-}

-- |
--
-- Module: Cryptography.Sodium.Bindings.SHA2
-- Description: Direct bindings to the SHA-256 and SHA-512 hashing functions implemented in Libsodium
-- Copyright: (C) Hécate Moonlight 2022
-- License: BSD-3-Clause
-- Maintainer: The Haskell Cryptography Group
-- Stability: Stable
-- Portability: GHC only
module Cryptography.Sodium.Bindings.SHA2
  ( -- * Introduction
    -- $introduction

    -- * SHA-256

    -- ** Single-part message
    cryptoHashSHA256,

    -- ** Multi-part messages
    CryptoHashSHA256State,
    cryptoHashSHA256Init,
    cryptoHashSHA256Update,
    cryptoHashSHA256Final,

    -- * SHA-512

    -- ** Single-part message
    cryptoHashSHA512,

    -- ** Multi-part messages
    CryptoHashSHA512State,
    cryptoHashSHA512Init,
    cryptoHashSHA512Update,
    cryptoHashSHA512Final,

    -- * Constants
    cryptoHashSHA256Bytes,
    cryptoHashSHA256StateBytes,
    cryptoHashSHA512Bytes,
    cryptoHashSHA512StateBytes,
  )
where

import Foreign (Ptr)
import Foreign.C (CInt (CInt), CSize (CSize), CUChar, CULLong (CULLong))

-- $introduction
--
-- The SHA-256 and SHA-512 functions are provided for interoperability with other applications. If you are
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
-- /See also:/ [crypto_hash_sha256()](https://doc.libsodium.org/advanced/sha-2_hash_function#sha-256)
--
-- @since 0.0.1.0
foreign import capi "sodium.h crypto_hash_sha256"
  cryptoHashSHA256 ::
    -- | A pointer to the hash of your data.
    Ptr CUChar ->
    -- | A pointer to the data you want to hash.
    Ptr CUChar ->
    -- | The length of the data you want to hash.
    CULLong ->
    -- | Returns 0 on success, -1 on error.
    IO CInt

-- | This is the opaque state held and used by the SHA-256 functions.
--
-- Its size is 'cryptoHashSHA256StateBytes'.
--
-- /See also:/ [crypto_hash_sha256_state](https://doc.libsodium.org/advanced/sha-2_hash_function#data-types)
--
-- @since 0.0.1.0
data CryptoHashSHA256State

-- | This function initializes the 'CryptoHashSHA256State' state.
--
-- Call this function on a 'Ptr CryptoHashSHA256State' before using it
-- as an argument in any other function in this module.
--
-- /See also:/ [crypto_hash_sha256_init()](https://doc.libsodium.org/advanced/sha-2_hash_function#sha-256)
--
-- @since 0.0.1.0
foreign import capi "sodium.h crypto_hash_sha256_init"
  cryptoHashSHA256Init ::
    -- | A pointer to an initialized hash state. Cannot be 'Foreign.nullPtr'.
    Ptr CryptoHashSHA256State ->
    -- | Returns 0 on success, -1 on error.
    IO CInt

-- | Add a new chunk to the message that will eventually be hashed.
--
-- After all parts have been supplied, 'cryptoHashSHA256Final' can be used to finalise the operation
-- and get the final hash.
--
-- /See also:/ [crypto_hash_sha256_update()](https://doc.libsodium.org/advanced/sha-2_hash_function#sha-256)
--
-- @since 0.0.1.0
foreign import capi "sodium.h crypto_hash_sha256_update"
  cryptoHashSHA256Update ::
    -- | A pointer to an initialized hash state. Cannot be 'Foreign.nullPtr'.
    Ptr CryptoHashSHA256State ->
    -- | A pointer to the new message chunk to process.
    Ptr CUChar ->
    -- | The length in bytes of the chunk.
    CULLong ->
    -- | Returns 0 on success, -1 on error.
    IO CInt

-- | Finalise the hashing of a message. The final hash is padded with extra zeros if necessary,
-- then put in a buffer.
--
-- After this operation, the buffer containing the 'CryptoHashSHA256State' is emptied and
-- cannot be relied upon.
--
-- /See also:/ [crypto_hash_sha256_final()](https://doc.libsodium.org/advanced/sha-2_hash_function#sha-256)
--
-- @since 0.0.1.0
foreign import capi "sodium.h crypto_hash_sha256_final"
  cryptoHashSHA256Final ::
    -- | A pointer to an initialized hash state. Cannot be 'Foreign.nullPtr'.
    Ptr CryptoHashSHA256State ->
    -- | The buffer in which the final hash is stored.
    Ptr CUChar ->
    -- | Returns 0 on success, -1 on error.
    IO CInt

-- | Hash the content of the second buffer and put the result in the first buffer.
--
-- /See also:/ [crypto_hash_sha512()](https://doc.libsodium.org/advanced/sha-2_hash_function#sha-512)
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
    -- | Returns 0 on success, -1 on error.
    IO CInt

-- | This is the opaque state held and used by the SHA-512 functions.
--
-- Its size is 'cryptoHashSHA512StateBytes'.
--
-- /See also:/ [crypto_hash_sha512_state](https://doc.libsodium.org/advanced/sha-2_hash_function#data-types)
--
-- @since 0.0.1.0
data CryptoHashSHA512State

-- | This function initializes the 'CryptoHashSHA512State' state.
--
-- Call this function on a 'Ptr CryptoHashSHA512State' before using it
-- as an argument in any other function in this module.
--
-- /See also:/ [crypto_hash_sha512_init()](https://doc.libsodium.org/advanced/sha-2_hash_function#sha-512)
--
-- @since 0.0.1.0
foreign import capi "sodium.h crypto_hash_sha512_init"
  cryptoHashSHA512Init ::
    -- | A pointer to an initialized hash state. Cannot be 'Foreign.nullPtr'.
    Ptr CryptoHashSHA512State ->
    -- | Returns 0 on success, -1 on error.
    IO CInt

-- | Add a new chunk to the message that will eventually be hashed.
--
-- After all parts have been supplied, 'cryptoHashSHA512Final' can be used to finalise the operation
-- and get the final hash.
--
-- /See also:/ [crypto_hash_sha512_update()](https://doc.libsodium.org/advanced/sha-2_hash_function#sha-512)
--
-- @since 0.0.1.0
foreign import capi "sodium.h crypto_hash_sha512_update"
  cryptoHashSHA512Update ::
    -- | A pointer to an initialized hash state. Cannot be 'Foreign.nullPtr'.
    Ptr CryptoHashSHA512State ->
    -- | A pointer to the new message chunk to process.
    Ptr CUChar ->
    -- | The length in bytes of the chunk.
    CULLong ->
    -- | Returns 0 on success, -1 on error.
    IO CInt

-- | Finalise the hashing of a message. The final hash is padded with extra zeros if necessary,
-- then put in a buffer.
--
-- After this operation, the buffer containing the 'CryptoHashSHA512State' is emptied and
-- cannot be relied upon.
--
-- /See also:/ [crypto_hash_sha512_final()](https://doc.libsodium.org/advanced/sha-2_hash_function#sha-512)
--
-- @since 0.0.1.0
foreign import capi "sodium.h crypto_hash_sha512_final"
  cryptoHashSHA512Final ::
    -- | A pointer to an initialized hash state. Cannot be 'Foreign.nullPtr'.
    Ptr CryptoHashSHA512State ->
    -- | The buffer in which the final hash is stored.
    Ptr CUChar ->
    -- | Returns 0 on success, -1 on error.
    IO CInt

---------------
-- Constants --
---------------

-- | The size of a SHA256-hashed message.
--
-- @since 0.0.1.0
foreign import capi "sodium.h value crypto_hash_sha256_BYTES"
  cryptoHashSHA256Bytes :: CSize

-- | The size of a 'CryptoHashSHA256State'.
--
-- @since 0.0.1.0
foreign import capi "sodium.h crypto_hash_sha256_statebytes"
  cryptoHashSHA256StateBytes :: CSize

-- | This constant represents the size of a pre-hashed message.
-- It is in use in the @ED25519ph@ multi-part signing system.
--
-- For more information, please consult the documentation of
-- "Cryptography.Sodium.Bindings.Signing".
--
-- @since 0.0.1.0
foreign import capi "sodium.h value crypto_hash_sha512_BYTES"
  cryptoHashSHA512Bytes :: CSize

-- | The size of a 'CryptoHashSHA512State'.
--
-- @since 0.0.1.0
foreign import capi "sodium.h crypto_hash_sha512_statebytes"
  cryptoHashSHA512StateBytes :: CSize
