{-# LANGUAGE ImportQualifiedPost #-}
{-# LANGUAGE TypeApplications #-}
{-# LANGUAGE ViewPatterns #-}

-- |
-- Module      : Sel.Internal.Instances
-- Description : Type class method implementations for pointer-backed types
-- Copyright   : (c) Jack Henahan, 2024
-- License     : BSD-3-Clause
-- Maintainer  : The Haskell Cryptography Group
-- Portability : GHC only
module Sel.Internal.Instances where

import Data.Base16.Types qualified as Base16
import Data.ByteString.Base16 qualified as Base16
import Data.ByteString.Internal (memcmp)
import Data.ByteString.Unsafe qualified as ByteString
import Data.Coerce (coerce)
import Foreign qualified
import Foreign.C (CChar, CSize, CUChar)
import Foreign.ForeignPtr (ForeignPtr)
import LibSodium.Bindings.Comparison (sodiumMemcmp)
import Sel.Internal.Scoped
import Sel.Internal.Scoped.Foreign

-- | Compare the contents of two byte arrays in constant time.
--
-- /See:/ [Constant-time test for equality](https://doc.libsodium.org/helpers#constant-time-test-for-equality)
--
-- @since 0.0.3.0
foreignPtrEqConstantTime :: ForeignPtr CUChar -> ForeignPtr CUChar -> CSize -> IO Bool
foreignPtrEqConstantTime p q size =
  fmap (== 0) . use $
    sodiumMemcmp <$> foreignPtr p <*> foreignPtr q <*> pure size

-- | Lexicographically compare the contents of two byte arrays.
--
-- ⚠️ Such comparisons are vulnerable to timing attacks, and should be
-- avoided for secret data.
--
-- @since 0.0.1.0
foreignPtrOrd :: ForeignPtr CUChar -> ForeignPtr CUChar -> CSize -> IO Ordering
foreignPtrOrd p q size =
  fmap (`compare` 0) . useM $
    memcmp
      <$> foreignPtr (coerce p)
      <*> foreignPtr (coerce q)
      <*> pure (fromIntegral size)

-- | Compare two byte arrays for lexicographic equality.
--
-- ⚠️ Such comparisons are vulnerable to timing attacks, and should be
-- avoided for secret data.
--
-- @since 0.0.1.0
foreignPtrEq :: ForeignPtr CUChar -> ForeignPtr CUChar -> CSize -> IO Bool
foreignPtrEq p q size = (== EQ) <$> foreignPtrOrd p q size

-- | Convert a @'ForeignPtr' a@ to a 'ByteString' of the given length
-- and render the hexadecimal-encoded bytes as a 'String'.
--
-- @since 0.0.1.0
foreignPtrShow :: ForeignPtr a -> CSize -> IO String
foreignPtrShow (Foreign.castForeignPtr @_ @CChar -> cstring) size =
  fmap (show . Base16.extractBase16 . Base16.encodeBase16')
    . useM
    $ curry ByteString.unsafePackMallocCStringLen
      <$> foreignPtr cstring
      <*> pure (fromIntegral size)
