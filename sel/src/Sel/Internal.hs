{-# LANGUAGE CApiFFI #-}
{-# LANGUAGE MultiWayIf #-}

module Sel.Internal where

import Foreign.C.Types (CSize(..), CInt(..))
import Foreign.Ptr (Ptr)
import Foreign.ForeignPtr (withForeignPtr, ForeignPtr)
-- | This calls to C's `memcmp` function, used in lieu of
-- libsodium's `memcmp` in cases when the return code is necessary.
foreign import capi unsafe "memcmp"
  memcmp :: Ptr a -> Ptr b -> CSize -> IO CInt

unsafeForeignPtrEq :: ForeignPtr a -> ForeignPtr a -> CSize -> IO Bool
unsafeForeignPtrEq fptr1 fptr2 size =
 withForeignPtr fptr1 $ \p ->
   withForeignPtr fptr2 $ \q ->
     do result <- memcmp p q size 
        return $ 0 == result

unsafeForeignPtrOrd :: ForeignPtr a -> ForeignPtr a -> CSize -> IO Ordering
unsafeForeignPtrOrd fptr1 fptr2 size =
 withForeignPtr fptr1 $ \p ->
   withForeignPtr fptr2 $ \q ->
     do result <- memcmp p q size 
        return $ if
          | result == 0 -> EQ
          | result < 0 -> LT
          | otherwise -> GT
