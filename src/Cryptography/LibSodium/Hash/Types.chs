module Cryptography.LibSodium.Hash.Types 
  ( Blake2bState(..)
  ) where

import Data.Array.Storable (StorableArray, withStorableArray)
import Data.Array.MArray (newListArray)
import Foreign (Storable(..))
import Foreign.Ptr (Ptr, castPtr, plusPtr)
import Data.Word (Word8)
import Foreign.C.Types (CSize, CUChar (..))
import Data.Foldable (traverse_)

import Cryptography.LibSodium.Orphans ()
#include "sodium.h"

-- | Wrapper holding the state for the Blake2b hashing algorithm.
--
-- C counterpart:
--
-- > typedef struct CRYPTO_ALIGN(64) crypto_generichash_blake2b_state {
-- >     unsigned char opaque[384];
-- > } crypto_generichash_blake2b_state;
--
-- @since 0.0.1.0
newtype Blake2bState = Blake2bState (StorableArray CSize CUChar)

-- @since 0.0.1.0
instance Storable Blake2bState where
  sizeOf _ = {#sizeof crypto_generichash_blake2b_state #}

  alignment _ = {#alignof crypto_generichash_blake2b_state #}

  peek :: Ptr Blake2bState -> IO Blake2bState
  peek ptr = do
    let bytePtr :: Ptr Word8 = castPtr ptr
    xs <- traverse (\i -> peek (plusPtr bytePtr i)) [0..383]
    Blake2bState <$> newListArray (0, 383) xs

  poke :: Ptr Blake2bState -> Blake2bState -> IO ()
  poke ptr (Blake2bState arr) = withStorableArray arr (go bytePtr)
    where
    bytePtr :: Ptr CUChar
    bytePtr = castPtr ptr

    go :: Ptr CUChar -> Ptr CUChar -> IO ()
    go outPtr arrPtr = traverse_
      (\i -> peek @CUChar (plusPtr arrPtr i) >>= poke (plusPtr outPtr i)) [0..383]
