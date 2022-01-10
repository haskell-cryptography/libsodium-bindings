{-# OPTIONS_GHC -Wno-orphans #-}
module Cryptography.LibSodium.Orphans where

import Data.Ix
import Foreign.C.Types
import GHC.Ix (Ix(..))

instance Ix CSize where
  range (CSize m, CSize n) = CSize <$> range (m, n)
  unsafeIndex (CSize m, CSize n) (CSize i) = unsafeIndex (m, n) i
  inRange (CSize m, CSize n) (CSize i) = inRange (m, n) i
