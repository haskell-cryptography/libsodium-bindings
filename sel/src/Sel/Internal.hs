{-# LANGUAGE BangPatterns #-}
{-# LANGUAGE ImportQualifiedPost #-}
{-# LANGUAGE KindSignatures #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TypeApplications #-}
{-# LANGUAGE ViewPatterns #-}

module Sel.Internal where

import Control.Monad (when)
import Control.Monad.IO.Class (MonadIO, liftIO)
import Control.Monad.Trans.Class (lift)
import Data.Base16.Types qualified as Base16
import Data.ByteString (StrictByteString)
import Data.ByteString.Base16 qualified as Base16
import Data.ByteString.Internal (memcmp)
import Data.ByteString.Internal qualified as ByteString
import Data.Coerce (coerce)
import Data.Kind (Type)
import Foreign (ForeignPtr, Ptr)
import Foreign qualified
import Foreign.C (CSize, CUChar, throwErrno)
import Foreign.C.Types (CChar)
import LibSodium.Bindings.Comparison (sodiumMemcmp)
import LibSodium.Bindings.SecureMemory (finalizerSodiumFree, sodiumFree, sodiumMalloc)
import Sel.Internal.Scoped
import Sel.Internal.Scoped.Foreign
import System.IO.Unsafe (unsafeDupablePerformIO)

-- | Compare the contents of two byte arrays in constant time.
--
-- /See:/ [Constant-time test for equality](https://doc.libsodium.org/helpers#constant-time-test-for-equality)
--
-- @since 0.0.3.0
foreignPtrEqConstantTime :: ForeignPtr CUChar -> ForeignPtr CUChar -> CSize -> Bool
foreignPtrEqConstantTime p q size =
  unsafeDupablePerformIO . fmap (== 0) . use $
    sodiumMemcmp <$> foreignPtr p <*> foreignPtr q <*> pure size

-- | Lexicographically compare the contents of two byte arrays.
--
-- ⚠️ Such comparisons are vulnerable to timing attacks, and should be
-- avoided for secret data.
--
-- @since 0.0.1.0
foreignPtrOrd :: ForeignPtr CUChar -> ForeignPtr CUChar -> CSize -> Ordering
foreignPtrOrd p q size =
  unsafeDupablePerformIO . fmap (`compare` 0) . useM $
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
foreignPtrEq :: ForeignPtr CUChar -> ForeignPtr CUChar -> CSize -> Bool
foreignPtrEq p q size = foreignPtrOrd p q size == EQ

-- | Convert a @'ForeignPtr' a@ to a 'ByteString' of the given length
-- and render the hexadecimal-encoded bytes as a 'String'.
--
-- @since 0.0.1.0
foreignPtrShow :: ForeignPtr a -> CSize -> String
foreignPtrShow (Foreign.castForeignPtr -> cstring) size =
  ByteString.unpackChars . Base16.extractBase16 . Base16.encodeBase16' $
    ByteString.fromForeignPtr cstring 0 (fromIntegral @CSize @Int size)

-- | Copy a byte array to a @libsodium@ pointer.
--
-- The size of the array is not checked. The input may be truncated if
-- it is too long, or an unchecked exception may be thrown if it is
-- too short.
--
-- @since 0.0.3.0
unsafeCopyToSodiumPointer :: CSize -> StrictByteString -> IO (ForeignPtr CUChar)
unsafeCopyToSodiumPointer size s = use $ do
  str <- unsafeCString s
  lift $ sodiumPointer size $ \k ->
    Foreign.copyArray
      (Foreign.castPtr @CUChar @CChar k)
      str
      (fromIntegral @CSize @Int size)

-- | Allocate secure memory and populate it with the provided action.
--
-- Memory is allocated with 'LibSodium.Bindings.SecureMemory.sodiumMalloc' (see notes).
--
-- A finalizer frees the memory when the key goes out of scope.
--
-- @since 0.0.3.0
sodiumPointer :: CSize -> (Ptr CUChar -> IO ()) -> IO (ForeignPtr CUChar)
sodiumPointer size action = do
  ptr <- sodiumMalloc size
  when (ptr == Foreign.nullPtr) $ do
    throwErrno "sodium_malloc"
  action ptr
  Foreign.newForeignPtr finalizerSodiumFree ptr

-- | Securely allocate an amount of memory with 'sodiumMalloc' and pass
-- a pointer to the region to the provided action.
-- The region is deallocated with 'sodiumFree' afterwards.
-- Do not try to jailbreak the pointer outside of the action,
-- this will not be pleasant.
allocateWith
  :: forall (a :: Type) (b :: Type) (m :: Type -> Type)
   . MonadIO m
  => CSize
  -- ^ Amount of memory to allocate
  -> (Ptr a -> m b)
  -- ^ Action to perform on the memory
  -> m b
allocateWith size action = do
  !ptr <- liftIO $ sodiumMalloc size
  !result <- action ptr
  liftIO $ sodiumFree ptr
  pure result
