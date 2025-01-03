{-# LANGUAGE CApiFFI #-}
{-# LANGUAGE Trustworthy #-}

-- | Module: LibSodium.Bindings.Comparison
-- Description: Helper functions for constant-time comparison
-- Copyright: (C) Koz Ross 2022, Jack Henahan 2025
-- License: BSD-3-Clause
-- Maintainer: koz.ross@retro-freedom.nz
-- Stability: Stable
-- Portability: GHC only
--
-- Secure comparison functions, designed to run in constant time for a given
-- input length.
module LibSodium.Bindings.Comparison
  ( sodiumMemcmp
  , sodiumCompare
  , sodiumIsZero
  )
where

import Foreign.C.Types (CInt (CInt), CSize (CSize), CUChar)
import Foreign.Ptr (Ptr)

-- | Compares the given amount of bytes at the given locations for equality.
-- Constant-time for any given length.
--
-- /See:/ [sodium_memcmp()](https://doc.libsodium.org/helpers#constant-time-test-for-equality)
--
-- @since 0.0.1.0
foreign import capi "sodium.h sodium_memcmp"
  sodiumMemcmp
    :: Ptr CUChar
    -- ^ First location with data to compare
    -> Ptr CUChar
    -- ^ Second location with data to compare
    -> CSize
    -- ^ How many bytes to compare
    -> CInt
    -- ^ 0 if all bytes match, -1 otherwise

-- | Lexicographically compares the requested bytes of the given
-- pointers in constant time.
--
-- /See:/ [sodium_compare()](https://libsodium.gitbook.io/doc/helpers#comparing-large-numbers)
--
-- @since 0.0.3.0
foreign import capi "sodium.h sodium_compare"
  sodiumCompare
    :: Ptr CUChar
    -- ^ First pointer data (lhs)
    -> Ptr CUChar
    -- ^ Second pointer data (rhs)
    -> CSize
    -- ^ Bytes to compare
    -> IO CInt
    -- ^ Comparison result
    -- lhs == rhs -> 0
    -- lhs < rhs -> -1
    -- lhs > rhs -> 1

-- | Checks if the given number of bytes at the given location are all equal to
-- zero. Constant-time for any given length.
--
-- /See:/ [sodium_is_zero()](https://doc.libsodium.org/helpers#testing-for-all-zeros)
--
-- @since 0.0.1.0
foreign import capi "sodium.h sodium_is_zero"
  sodiumIsZero
    :: Ptr CUChar
    -- ^ Location with data to check
    -> CSize
    -- ^ How many bytes to check
    -> CInt
    -- ^ 1 if all the bytes were zeroes, 0 otherwise
