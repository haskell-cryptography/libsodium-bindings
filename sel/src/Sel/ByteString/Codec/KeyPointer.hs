{-# LANGUAGE AllowAmbiguousTypes #-}
{-# LANGUAGE ConstraintKinds #-}
{-# LANGUAGE DataKinds #-}
{-# LANGUAGE ExplicitNamespaces #-}
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE KindSignatures #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TypeApplications #-}
{-# LANGUAGE UndecidableInstances #-}

-- |
-- Module      : Sel.ByteString.Codec.KeyPointer
-- Description : Pointer utilities for cryptographic key material
-- Copyright   : (c) Jack Henahan, 2024
-- License     : BSD-3-Clause
-- Maintainer  : The Haskell Cryptography Group
-- Portability : GHC only
--
-- This module provides a type class for describing pointer sizes for
-- cryptographic key material along with utilities for creating such
-- pointers and deriving common instances based on the pointer size.
module Sel.ByteString.Codec.KeyPointer
  ( -- * Key material pointer utilities
    KeyPointerSize (..)
  , keyPointer
  , keyPointerLength

    -- ** Deriving instances
  , KeyPointer (..)
  , type KeyCoerce
  , type ComparisonImplementation (..)
  )
where

import Data.Coerce (Coercible, coerce)
import Data.Kind (Type)
import Foreign (ForeignPtr, mallocForeignPtrBytes)
import Foreign.C (CSize, CUChar)
import Sel.Internal.Instances
import System.IO.Unsafe (unsafeDupablePerformIO)

-- | Define the size of the pointer for some key material.
--
-- @since 0.0.3.0
class KeyPointerSize a where
  keyPointerSize :: CSize
  -- ^ @since 0.0.3.0

-- | Length of the pointer for some key material.
--
-- @since 0.0.3.0
keyPointerLength :: forall a. KeyPointerSize a => Int
keyPointerLength = fromIntegral @CSize @Int (keyPointerSize @a)

-- | Allocate a 'ForeignPtr' 'CUChar' for some key material.
--
-- @since 0.0.3.0
keyPointer :: forall a. KeyPointerSize a => IO (ForeignPtr CUChar)
keyPointer = mallocForeignPtrBytes $ keyPointerLength @a

-- | Tag denoting the characteristics of the desired pointer comparison.
--
-- Secret material should always use 'Constant', but public material
-- may use short-circuiting comparison for performance unless
-- otherwise specified by the @libsodium@ docs.
--
-- @since 0.0.3.0
data ComparisonImplementation
  = -- | Use byte-wise (short-circuiting) comparison.
    --
    -- @since 0.0.3.0
    ShortCircuiting
  | -- | Use constant-time comparison.
    --
    -- @since 0.0.3.0
    ConstantTime

-- | A wrapper to enable deriving instances from the size of a key
-- material pointer.
--
-- === Example
--
-- @
-- newtype SomeKeyMaterial = SomeKeyMaterial (ForeignPtr CUChar)
--   deriving (Eq, Ord) via (KeyPointer SomeKeyMaterial ShortCircuiting)
--
-- instance KeyPointerSize SomeKeyMaterial where
--   keyPointerSize :: CSize
--   keyPointerSize = {- get your size from the FFI bindings -}
-- @
--
-- @since 0.0.3.0
newtype KeyPointer (a :: Type) (cmp :: ComparisonImplementation) = KeyPointer a

-- | Demand a known pointer size and an underlying pointer coercible
-- to a @'ForeignPtr' 'CUChar'@.
--
-- @since 0.0.3.0
type KeyCoerce a = (KeyPointerSize a, Coercible a (ForeignPtr CUChar))

-- | Byte-wise (short-circuiting) pointer equality.
--
-- ⚠️ This instance is vulnerable to timing attacks. Prefer the
-- 'ConstantTime' instance for secret material.
--
-- @since 0.0.3.0
instance KeyCoerce a => Eq (KeyPointer a ShortCircuiting) where
  a == b =
    unsafeDupablePerformIO $
      foreignPtrEq (coerce a) (coerce b) (keyPointerSize @a)

-- | Constant-time pointer equality.
--
-- @since 0.0.3.0
instance KeyCoerce a => Eq (KeyPointer a ConstantTime) where
  a == b =
    unsafeDupablePerformIO $
      foreignPtrEqConstantTime (coerce a) (coerce b) (keyPointerSize @a)

-- | Byte-wise (short-circuiting) pointer comparison.
--
-- ⚠️ This instance is vulnerable to timing attacks.
--
-- @since 0.0.3.0
instance (KeyCoerce a, Eq (KeyPointer a cmp)) => Ord (KeyPointer a cmp) where
  compare a b =
    unsafeDupablePerformIO $
      foreignPtrOrd (coerce a) (coerce b) (keyPointerSize @a)
