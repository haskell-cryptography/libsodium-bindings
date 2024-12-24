{-# LANGUAGE BangPatterns #-}
{-# LANGUAGE KindSignatures #-}
{-# LANGUAGE ScopedTypeVariables #-}

module Sel.Internal where

import Control.Monad.IO.Class (MonadIO, liftIO)
import Data.Kind (Type)
import Foreign (Ptr)
import Foreign.C (CSize)
import LibSodium.Bindings.SecureMemory (sodiumFree, sodiumMalloc)

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
