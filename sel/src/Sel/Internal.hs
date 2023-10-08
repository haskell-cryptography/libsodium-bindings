{-# LANGUAGE BangPatterns #-}
{-# LANGUAGE CApiFFI #-}
{-# LANGUAGE KindSignatures #-}
{-# LANGUAGE MultiWayIf #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TypeApplications #-}

module Sel.Internal where

import Control.Monad.IO.Class (MonadIO, liftIO)
import qualified Data.Base16.Types as Base16
import qualified Data.ByteString.Base16 as Base16
import qualified Data.ByteString.Internal as BS
import Data.Kind (Type)
import Foreign (Ptr, castForeignPtr)
import Foreign.C.Types (CInt (CInt), CSize (CSize))
import Foreign.ForeignPtr (ForeignPtr, withForeignPtr)
import LibSodium.Bindings.SecureMemory (sodiumFree, sodiumMalloc)

-- | This calls to C's @memcmp@ function, used in lieu of
-- libsodium's @memcmp@ in cases when the return code is necessary.
foreign import capi unsafe "string.h memcmp"
  memcmp :: Ptr a -> Ptr b -> CSize -> IO CInt

-- | Compare if the contents of two @ForeignPtr@s are equal.
foreignPtrEq :: ForeignPtr a -> ForeignPtr a -> CSize -> IO Bool
foreignPtrEq fptr1 fptr2 size =
  withForeignPtr fptr1 $ \p ->
    withForeignPtr fptr2 $ \q ->
      do
        result <- memcmp p q size
        return $ 0 == result

-- | Compare the contents of two @ForeignPtr@s using lexicographical ordering.
foreignPtrOrd :: ForeignPtr a -> ForeignPtr a -> CSize -> IO Ordering
foreignPtrOrd fptr1 fptr2 size =
  withForeignPtr fptr1 $ \p ->
    withForeignPtr fptr2 $ \q ->
      do
        result <- memcmp p q size
        return $
          if
              | result == 0 -> EQ
              | result < 0 -> LT
              | otherwise -> GT

foreignPtrShow :: ForeignPtr a -> CSize -> String
foreignPtrShow fptr size =
  BS.unpackChars . Base16.extractBase16 . Base16.encodeBase16' $
    BS.fromForeignPtr (Foreign.castForeignPtr fptr) 0 (fromIntegral @CSize @Int size)

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
