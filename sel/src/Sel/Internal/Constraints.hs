{-# LANGUAGE CPP #-}
{-# LANGUAGE ConstraintKinds #-}
{-# LANGUAGE DataKinds #-}
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE StandaloneKindSignatures #-}
{-# LANGUAGE TypeOperators #-}

-- |
-- Module      : Sel.Internal.Constraints
-- Description : Unsatisfiable instance constraints
-- Copyright   : (c) Jack Henahan, 2024
-- License     : BSD-3-Clause
-- Maintainer  : The Haskell Cryptography Group
-- Portability : GHC only
--
-- This module provides a constraint for making instances illegal with
-- a custom error message, along with type-operator constraints for
-- common instances with escape hatches.
module Sel.Internal.Constraints
  ( type (:!!!:) -- ^ @since 0.0.3.0
  , type (:<:) -- ^ @since 0.0.3.0
  , illegal -- ^ @since 0.0.3.0
  )
where

import Data.Kind (Constraint, Type)
import GHC.TypeError

-- | @since 0.0.3.0
type ErrorImplementation :: ErrorMessage -> Constraint
#if MIN_VERSION_base(4, 19, 0)
type ErrorImplementation = Unsatisfiable
#else
type ErrorImplementation msg = TypeError msg
#endif

-- | @since 0.0.3.0
illegal :: ErrorImplementation msg => a
#if MIN_VERSION_base(4, 19, 0)
illegal = unsatisfiable
#else
illegal = undefined
#endif

-- | Prohibit undecorated instances
--
-- @since 0.0.3.0
type (:!!!:) :: Type -> Type -> Constraint
type underlying :!!!: wrapper =
  ErrorImplementation
    ( Text "Transmitting a "
        :<>: ShowType underlying
        :<>: Text " is a security risk!"
        :$$: Text "Wrap with "
          :<>: ShowType wrapper
          :<>: Text " to make this risk more obvious."
    )

-- | Prohibit 'Ord' instances for types vulnerable to timing attacks.
--
-- @since 0.0.3.0
type (:<:) :: Type -> Type -> Constraint
type underlying :<: wrapper =
  ErrorImplementation
    ( Text "Comparing "
        :<>: ShowType underlying
        :<>: Text " is vulnerable to timing attacks!"
        :$$: Text "Wrap with "
          :<>: ShowType wrapper
          :<>: Text " if you are sure you need this."
    )
