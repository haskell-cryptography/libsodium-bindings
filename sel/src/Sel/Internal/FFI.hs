{-# LANGUAGE CApiFFI #-}

-- |
-- Module      : Sel.Internal.FFI
-- Description : Internal FFI bindings
-- Copyright   : (c) Jack Henahan, 2024
-- License     : BSD-3-Clause
-- Maintainer  : The Haskell Cryptography Group
-- Portability : GHC only
--
-- This module provides FFI bindings for functions that may otherwise
-- be available in GHC libraries but are documented as unstable so
-- that we might control any breaking changes rather than subject
-- ourselves to drift during compiler upgrades.
module Sel.Internal.FFI where

import Foreign (Ptr)
import Foreign.C (CInt (CInt), CSize (CSize), CUChar)

-- | Use @'memcmp'@ if you need lexicographical comparison of byte
-- arrays representing non-sensitive data, e.g., when implementing
-- equality and ordering.
--
-- ⚠️ Do not use @'memcmp'@ for data vulnerable to timing attacks. Use
-- @'LibSodium.Bindings.Comparison.sodiumMemcmp'@ for constant-time
-- comparison. Note that constant-time comparison is only appropriate
-- for equality tests.
--
-- /See:/ [@memcmp@](https://en.cppreference.com/w/c/string/byte/memcmp)
foreign import capi unsafe "string.h memcmp"
  memcmp
    :: Ptr CUChar
    -- ^ lhs
    -> Ptr CUChar
    -- ^ rhs
    -> CSize
    -- ^ bytes to compare
    -> IO CInt
    -- ^ comparison result
    -- lhs < rhs -> result < 0
    -- lhs == rhs -> result == 0
    -- lhs > rhs -> result > 0

-- | Copy bytes into a target array from some source array.
--
-- /See:/ [@memcpy@](https://en.cppreference.com/w/c/string/byte/memcpy)
foreign import capi unsafe "string.h memcpy"
  memcpy
    :: Ptr CUChar
    -- ^ destination
    -> Ptr CUChar
    -- ^ source
    -> CSize
    -- ^ bytes to copy
    -> IO ()
