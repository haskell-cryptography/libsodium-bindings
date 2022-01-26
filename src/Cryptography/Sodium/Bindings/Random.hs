{-# LANGUAGE CApiFFI #-}
{-# LANGUAGE Safe #-}

-- | Module: Cryptography.Sodium.Bindings.Random
-- Description: Secure random number generation
-- Copyright: (C) Koz Ross 2022
-- License: BSD-3-Clause
-- Maintainer: koz.ross@retro-freedom.nz
-- Stability: Stable
-- Portability: GHC only
--
-- A collection of functions for securely generating unpredictable data. This
-- uses the best option on each platform, as follows:
--
-- * On Windows, @RtlGenRandom@.
-- * On FreeBSD and Linux, @getrandom@ syscall.
-- * On other UNIX platforms, @\/dev\/urandom@.
module Cryptography.Sodium.Bindings.Random
  ( randombytesRandom,
    randombytesUniform,
    randombytesBuf,
  )
where

import Data.Word (Word32, Word8)
import Foreign.C.Types (CSize (CSize))
import Foreign.Ptr (Ptr)

-- | Produces an unpredictable four-byte value.
--
-- = Corresponds to
--
-- [@randombytes_random@](https://libsodium.gitbook.io/doc/generating_random_data#usage)
--
-- @since 1.0
foreign import capi "sodium.h randombytes_random"
  randombytesRandom :: IO Word32

-- | Produces an unpredictable four-byte value not larger than the argument. This
-- function guarantees a uniform distribution on results, even if the upper
-- limit is not a power of 2.
--
-- = Corresponds to
--
-- [@randombytes_uniform@](https://libsodium.gitbook.io/doc/generating_random_data#usage)
--
-- @since 1.0
foreign import capi "sodium.h randombytes_uniform"
  randombytesUniform ::
    -- | upper limit (exclusive)
    Word32 ->
    IO Word32

-- | Fills a buffer of the given size with unpredictable bytes.
--
-- = Corresponds to
--
-- [@randombytes_buf@](https://libsodium.gitbook.io/doc/generating_random_data#usage)
--
-- @since 1.0
foreign import capi "sodium.h randombytes_buf"
  randombytesBuf ::
    -- | Out-parameter to fill
    Ptr Word8 ->
    -- | How many bytes to generate
    CSize ->
    -- | No meaningful return value
    IO ()
