{-# LANGUAGE ImportQualifiedPost #-}

-- |
-- Module      : Sel.Internal.Scoped.Foreign
-- Description : Scoped wrappers around pointer manipulation
-- Copyright   : (c) Jack Henahan, 2024
-- License     : BSD-3-Clause
-- Maintainer  : The Haskell Cryptography Group
-- Portability : GHC only
--
-- This module wraps some common points of contact with 'Ptr',
-- 'ForeignPtr', and friends up in 'Scoped' for the sake of not saying
-- 'lift' absolutely everywhere.
module Sel.Internal.Scoped.Foreign where

import Control.Monad.Trans.Class (lift)
import Data.ByteString (StrictByteString)
import Data.ByteString.Unsafe qualified as ByteString
import Foreign (ForeignPtr, Ptr, Storable)
import Foreign qualified
import Foreign.C (CString, CStringLen)
import Sel.Internal.Scoped

-- | @since 0.0.3.0
foreignPtr :: ForeignPtr a -> Scoped IO (Ptr a)
foreignPtr fptr = Scoped $ Foreign.withForeignPtr fptr

-- | @since 0.0.3.0
unsafeCStringLen :: StrictByteString -> Scoped IO CStringLen
unsafeCStringLen bs = Scoped $ ByteString.unsafeUseAsCStringLen bs

-- | @since 0.0.3.0
unsafeCString :: StrictByteString -> Scoped IO CString
unsafeCString bs = Scoped $ ByteString.unsafeUseAsCString bs

-- | @since 0.0.3.0
mallocBytes :: Int -> Scoped IO (Ptr a)
mallocBytes = lift . Foreign.mallocBytes

-- | @since 0.0.3.0
mallocForeignPtrBytes :: Int -> Scoped IO (ForeignPtr a)
mallocForeignPtrBytes len = lift $ Foreign.mallocForeignPtrBytes len

-- | @since 0.0.3.0
copyArray :: Storable a => Ptr a -> Ptr a -> Int -> Scoped IO ()
copyArray target source len = lift $ Foreign.copyArray target source len
