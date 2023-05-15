-- |
-- Module: Sel.Hashing.SHA2.Internal
-- Description: Common structures for the SHA-2 family
-- Copyright: (C) Hécate Moonlight 2022
-- License: BSD-3-Clause
-- Maintainer: The Haskell Cryptography Group
-- Portability: GHC only
module Sel.Hashing.SHA2.Internal
  ( Hash
  ) where

import Foreign (ForeignPtr)
import Foreign.C.Types (CUChar)

newtype Hash = SHA2Hash (ForeignPtr CUChar)
