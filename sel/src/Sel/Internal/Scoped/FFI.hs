{-# LANGUAGE ImportQualifiedPost #-}

-- |
-- Module      : Sel.Internal.Scoped.FFI
-- Description : Scoped FFI wrappers
-- Copyright   : (c) Jack Henahan, 2024
-- License     : BSD-3-Clause
-- Maintainer  : The Haskell Cryptography Group
-- Portability : GHC only
module Sel.Internal.Scoped.FFI where

import Control.Monad.Trans.Class (lift)
import Foreign (Ptr)
import Foreign.C (CSize, CUChar)
import Sel.Internal.FFI qualified as FFI
import Sel.Internal.Scoped

-- | @since 0.0.3.0
memcpy :: Ptr CUChar -> Ptr CUChar -> CSize -> Scoped IO ()
memcpy target source targetLength = lift $ FFI.memcpy target source targetLength
