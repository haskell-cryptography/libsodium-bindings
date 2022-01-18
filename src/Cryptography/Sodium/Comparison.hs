{-# LANGUAGE CApiFFI #-}
{-# LANGUAGE Trustworthy #-}

-- | Module: Cryptography.Sodium.Comparison
-- Description: Helper functions for constant-time comparison
-- Copyright: (C) Koz Ross 2022
-- License: BSD-3-Clause
-- Maintainer: koz.ross@retro-freedom.nz
-- Stability: Stable
-- Portability: GHC only
--
-- Secure comparison functions, designed to run in constant time for a given
-- input length.
module Cryptography.Sodium.Comparison
  ( sodiumMemcmp,
    sodiumIsZero,
  )
where

import Foreign.C.Types (CInt (CInt), CSize (CSize), CUChar)
import Foreign.Ptr (Ptr)

-- | Compares the given amount of bytes at the given locations for equality.
-- Constant-time for any given length.
--
-- = Corresponds to
--
-- [@sodium_memcmp@](https://libsodium.gitbook.io/doc/helpers#constant-time-test-for-equality)
--
-- @since 1.0
foreign import capi "sodium.h sodium_memcmp"
  sodiumMemcmp ::
    -- | First location with data to compare
    Ptr CUChar ->
    -- | Second location with data to compare
    Ptr CUChar ->
    -- | How many bytes to compare
    CSize ->
    -- | 0 if all bytes match, -1 otherwise
    CInt

-- | Checks if the given number of bytes at the given location are all equal to
-- zero. Constant-time for any given length.
--
-- = Corresponds to
--
-- [@sodium_is_zero@](https://libsodium.gitbook.io/doc/helpers#testing-for-all-zeros)
--
-- @since 1.0
foreign import capi "sodium.h sodium_is_zero"
  sodiumIsZero ::
    -- | Location with data to check
    Ptr CUChar ->
    -- | How many bytes to check
    CSize ->
    -- | 1 if all the bytes were zeroes, 0 otherwise
    CInt
