{-# LANGUAGE InstanceSigs #-}
{-# LANGUAGE PolyKinds #-}
{-# LANGUAGE RankNTypes #-}
{-# LANGUAGE StandaloneKindSignatures #-}
{-# LANGUAGE TypeFamilies #-}
{-# LANGUAGE TypeOperators #-}
{-# LANGUAGE UndecidableInstances #-}

-- |
-- Module      : Sel.Internal.Scoped
-- Description : Continuation-passing utilities
-- Copyright   : (c) Jack Henahan, 2024
-- License     : BSD-3-Clause
-- Maintainer  : The Haskell Cryptography Group
-- Portability : GHC only
--
-- This module implements a version of @Codensity@, modeling delimited
-- continuations. Useful for avoiding extreme rightward drift in
-- chains of @withForeignPtr@ and friends.
module Sel.Internal.Scoped where

import Control.Monad (ap, void)
import Control.Monad.IO.Class (MonadIO (liftIO))
import Control.Monad.Trans.Class (MonadTrans (lift))
import Data.Kind (Type)
import Data.Type.Equality (type (~~))
import GHC.Exts (RuntimeRep, TYPE)

-- | @since 0.0.3.0
type Scoped :: forall {k} {rep :: RuntimeRep}. (k -> TYPE rep) -> Type -> Type
newtype Scoped m a = Scoped {runScoped :: forall b. (a -> m b) -> m b}

-- | @since 0.0.3.0
instance Functor (Scoped f) where
  fmap f (Scoped m) = Scoped $ \k -> m (k . f)
  {-# INLINE fmap #-}

-- | @since 0.0.3.0
instance Applicative (Scoped f) where
  pure a = Scoped $ \k -> k a
  {-# INLINE pure #-}

  (<*>) = ap
  {-# INLINE (<*>) #-}

-- | @since 0.0.3.0
instance Monad (Scoped f) where
  Scoped m >>= f = Scoped $ \k ->
    m $ \a -> runScoped (f a) k
  {-# INLINE (>>=) #-}

-- | @since 0.0.3.0
instance (MonadIO m', m' ~~ m) => MonadIO (Scoped m) where
  liftIO = lift . liftIO
  {-# INLINE liftIO #-}

-- | @since 0.0.3.0
instance MonadTrans Scoped where
  lift m = Scoped (m >>=)
  {-# INLINE lift #-}

-- | @since 0.0.3.0
reset :: Monad m => Scoped m a -> Scoped m a
reset = lift . use

-- | @since 0.0.3.0
shift :: Applicative m => (forall b. (a -> m b) -> Scoped m b) -> Scoped m a
shift f = Scoped $ use . f

-- | @since 0.0.3.0
use :: Applicative m => Scoped m a -> m a
use (Scoped m) = m pure

-- | @since 0.0.3.0
useM :: Monad m => Scoped m (m a) -> m a
useM f = use $ f >>= lift

-- | @since 0.0.3.0
use_ :: Applicative m => Scoped m a -> m ()
use_ = void . use

-- | @since 0.0.3.0
useM_ :: Monad m => Scoped m (m a) -> m ()
useM_ = void . useM
