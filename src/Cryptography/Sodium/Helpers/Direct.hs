{-# LANGUAGE CApiFFI #-}

module Cryptography.Sodium.Helpers.Direct
  ( -- * Comparison
    sodiumMemcmp,

    -- * Hex conversion
    sodiumBinToHex,
  )
where

import Foreign.C.Types
  ( CChar,
    CInt (CInt),
    CSize (CSize),
    CUChar,
  )
import Foreign.Ptr (Ptr)

-- | @since 1.0
foreign import capi "sodium.h sodium_memcmp"
  sodiumMemcmp ::
    Ptr CUChar ->
    Ptr CUChar ->
    CSize ->
    CInt

-- | @since 1.0
foreign import capi "sodium.h sodium_bin2hex"
  sodiumBinToHex ::
    Ptr CChar ->
    CSize ->
    Ptr CUChar ->
    CSize ->
    IO (Ptr CChar)
