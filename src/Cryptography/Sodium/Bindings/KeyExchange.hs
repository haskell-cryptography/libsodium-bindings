{-# LANGUAGE CApiFFI #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE Trustworthy #-}

-- |
--
-- Module: Cryptography.Sodium.Bindings.KeyExchange
-- Description: Direct bindings to the Key Exchange functions implemented in Libsodium
-- Copyright: (C) Hécate Moonlight 2022
-- License: BSD-3-Clause
-- Maintainer: The Haskell Cryptography Group
-- Stability: Stable
-- Portability: GHC only
module Cryptography.Sodium.Bindings.KeyExchange
  ( -- * Introduction
    -- $introduction

    -- * Key Exchange
    cryptoKXKeyPair,
    cryptoKXSeedKeypair,

    -- ** Client
    cryptoKXClientSessionKeys,

    -- ** Server
    cryptoKXServerSessionKeys,

    -- ** Constants
    cryptoKXPublicKeyBytes,
    cryptoKXSecretKeyBytes,
    cryptoKXSeedBytes,
    cryptoKXSessionKeyBytes,
    cryptoKXPrimitive,
  )
where

import Foreign (Ptr)
import Foreign.C (CInt (CInt), CSize (CSize), CUChar, CULLong (CULLong))

-- $introduction
--
-- The Key Exchange API allows two parties to securely compute a set of shared keys using their peer's public key, and
-- their own secret key.

-- | Create a new key pair.
--
-- This function takes pointers to two empty buffers that will hold (respectively) the public and secret keys.
-- The pointers to these buffers are guaranteed not to be 'Foreign.nullPtr'
--
-- @since 0.0.1.0
foreign import capi "sodium.h crypto_kx_keypair"
  cryptoKXKeyPair ::
    -- | The buffer that will hold the public key, of size 'cryptoKXPublicKeyBytes'.
    -- It cannot be a 'Foreign.nullPtr'.
    Ptr CUChar ->
    -- | The buffer that will hold the secret key, of size 'cryptoKXSecretKeyBytes'.
    -- It cannot be a 'Foreign.nullPtr'.
    Ptr CUChar ->
    -- | Returns 0 on success, -1 on error.
    IO CInt

-- | Create a new key pair from a seed.
--
-- This function takes pointers to two empty buffers that will hold (respectively) the public and secret keys,
-- as well as the seed from which these keys will be derived.
--
-- The pointers to these buffers are guaranteed not to be 'Foreign.nullPtr'
--
-- /See also:/ [crypto_kx_seed_keypair()](https://doc.libsodium.org/key_exchange#usage)
--
-- @since 0.0.1.0
foreign import capi "sodium.h crypto_kx_seed_keypair"
  cryptoKXSeedKeypair ::
    -- | The buffer that will hold the public key, of size 'cryptoKXPublicKeyBytes'.
    -- It cannot be a 'Foreign.nullPtr'.
    Ptr CUChar ->
    -- | The buffer that will hold the secret key, of size 'cryptoKXSecretKeyBytes'.
    -- It cannot be a 'Foreign.nullPtr'.
    Ptr CUChar ->
    -- | The pointer to the seed from which the keys are derived.
    -- It cannot be a 'Foreign.nullPtr'.
    Ptr CUChar ->
    -- | Returns 0 on success, -1 on error.
    IO CInt

-- | Compute a pair of shared session keys (secret and public) of length 'cryptoKXSessionKeyBytes' bytes long.
--
-- These session keys are computed using:
--
-- * The client's public key
-- * The client's secret key
-- * The server's public key
--
-- The shared secret key should be used by the client to receive data from the server, whereas the shared
-- public key should be used for data flowing to the server.
--
-- /See also:/ [crypto_kx_client_session_keys()](https://doc.libsodium.org/key_exchange#usage)
--
-- @since 0.0.1.0
foreign import capi "sodium.h crypto_kx_client_session_keys"
  cryptoKXClientSessionKeys ::
    -- | A pointer to the buffer that will hold the shared secret key
    Ptr CUChar ->
    -- | A pointer to the buffer that will hold the shared public key
    Ptr CUChar ->
    -- | A pointer to the client's public key, of size 'cryptoKXPublicKeyBytes' bytes.
    Ptr CUChar ->
    -- | A pointer to the client's secret key, of size 'cryptoKXSecretKeyBytes bytes.
    Ptr CUChar ->
    -- | A pointer to the server's public key, of size 'cryptoKXPublicKeyBytes' bytes.
    Ptr CUChar ->
    -- | Returns 0 on success, -1 on error, such as when the server's public key is not acceptable.
    IO CInt
