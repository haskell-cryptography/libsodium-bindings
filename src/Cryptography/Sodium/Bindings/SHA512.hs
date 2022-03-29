{-# LANGUAGE CApiFFI #-}
{-# LANGUAGE Trustworthy #-}

-- |
--
-- Module: Cryptography.Sodium.Bindings.SHA512
-- Description: Direct bindings to the public-key signing algorithm ed25519 implemented in Libsodium
-- Copyright: (C) Hécate Moonlight 2022
-- License: BSD-3-Clause
-- Maintainer: The Haskell Cryptography Group
-- Stability: Stable
-- Portability: GHC only
module Cryptography.Sodium.Bindings.SHA512
  ( -- * Introduction
    -- $introduction
    CryptoHashSHA512State (..),
    cryptoHashSHA512Bytes,
    cryptoHashSHA512,
    cryptoHashSHA512Init,
    cryptoHashSHA512Update,
    cryptoHashSHA512Final,
  )
where

import Foreign (Ptr, Word64, Word8)
import Foreign.C (CInt (..), CSize (..), CUChar (..), CULLong (..))

-- $introduction
--
-- The SHA-512 functions are provided for interoperability with other applications. If you are
-- looking for a generic hash function and not specifically SHA-2, using
-- 'Cryptography.Sodium.Bindings.GenericHashing' (BLAKE2b) might be a better choice. These functions
-- are also not suitable for hashing passwords or deriving keys from passwords. Use
-- 'Cryptography.Sodium.Bindings.PasswordHashing' instead.
--
-- These functions are not keyed and are thus deterministic. In addition, the untruncated versions
-- are vulnerable to length extension attacks. A message can be hashed in a single pass, but a
-- streaming API is also available to process a message as a sequence of multiple chunks.

data CryptoHashSHA512State = CryptoHashSHA512State
  { state :: Word64,
    count :: Word64,
    buf :: Word8
  }

foreign import capi "sodium.h value crypto_hash_sha512_BYTES"
  cryptoHashSHA512Bytes :: CSize

foreign import capi "sodium.h crypto_hash_sha512"
  cryptoHashSHA512 ::
    -- | @out@ parameter. Cannot be @NULL@.
    Ptr CUChar ->
    -- | @in@ parameter.
    Ptr CUChar ->
    -- | @inlen@ parameter
    CULLong ->
    IO CInt

foreign import capi "sodium.h crypto_hash_sha512_init"
  cryptoHashSHA512Init ::
    -- | @state@ parameter. Cannot be @NULL@.
    Ptr CryptoHashSHA512State ->
    IO CInt

foreign import capi "sodium.h crypto_hash_sha512_update"
  cryptoHashSHA512Update ::
    -- | @state@ parameter. Cannot be @NULL@.
    Ptr CryptoHashSHA512State ->
    -- | @in@ parameter.
    Ptr CUChar ->
    -- | @inlen@ parameter
    CULLong ->
    IO CInt

foreign import capi "sodium.h crypto_hash_sha512_final"
  cryptoHashSHA512Final ::
    -- | @state@ parameter. Cannot be @NULL@.
    Ptr CryptoHashSHA512State ->
    -- | @out@ parameter.
    Ptr CUChar ->
    IO CInt
