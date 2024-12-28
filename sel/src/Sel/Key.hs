{-# LANGUAGE AllowAmbiguousTypes #-}
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE ImportQualifiedPost #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TypeApplications #-}

-- |
-- Module      : Sel.Key
-- Description : Key material utilities
-- Copyright   : (c) Jack Henahan, 2024
-- License     : BSD-3-Clause
-- Maintainer  : The Haskell Cryptography Group
-- Portability : GHC only
module Sel.Key
  ( -- * Key material utilities
    toKey
  , newKeyWith
  )
where

import Control.Monad (when)
import Data.ByteString (StrictByteString)
import Data.ByteString.Unsafe qualified as ByteString
import Data.Coerce (coerce)
import Foreign (Ptr, castPtr, copyArray, newForeignPtr, nullPtr)
import Foreign.C (CChar, CSize, CUChar, throwErrno)
import LibSodium.Bindings.SecureMemory (finalizerSodiumFree, sodiumMalloc)
import Sel.ByteString.Codec.KeyMaterialDecodeError
import Sel.ByteString.Codec.KeyPointer
import System.IO.Unsafe (unsafeDupablePerformIO)

-- | Copy a byte array as key material.
--
-- The size of the array is checked against the size of the target
-- pointer.
--
-- @since 0.0.3.0
toKey :: forall a. KeyCoerce a => StrictByteString -> Either KeyMaterialDecodeError a
toKey s = unsafeCopyKey <$> validKeyMaterialLength @a s

-- | Copy a byte array as key material.
--
-- The size of the array is not checked. The input may be truncated if
-- it is too long, or an unchecked exception may be thrown if it is
-- too short.
--
-- @since 0.0.3.0
unsafeCopyKey :: forall a. KeyCoerce a => StrictByteString -> a
unsafeCopyKey s = unsafeDupablePerformIO $
  ByteString.unsafeUseAsCString s $ \str ->
    newKeyWith @a $ \k ->
      Foreign.copyArray
        (Foreign.castPtr @CUChar @CChar k)
        str
        (fromIntegral @CSize @Int (keyPointerSize @a))

-- | Allocate memory for key material and populate it with the provided action.
--
-- Memory is allocated with 'LibSodium.Bindings.SecureMemory.sodiumMalloc' (see notes).
--
-- A finalizer frees the memory when the key goes out of scope.
--
-- @since 0.0.3.0
newKeyWith :: forall a. KeyCoerce a => (Ptr CUChar -> IO ()) -> IO a
newKeyWith action = do
  ptr <- sodiumMalloc (keyPointerSize @a)
  when (ptr == Foreign.nullPtr) $ do
    throwErrno "sodium_malloc"
  fptr <- Foreign.newForeignPtr finalizerSodiumFree ptr
  action ptr
  pure $ coerce fptr
