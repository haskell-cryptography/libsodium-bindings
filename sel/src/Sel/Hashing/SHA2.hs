-- |
-- Module: Sel.Hashing.SHA2
-- Description: SHA-2 family of hashing algorithms.
-- Copyright: (C) Hécate Moonlight 2022
-- License: BSD-3-Clause
-- Maintainer: The Haskell Cryptography Group
-- Portability: GHC only
module Sel.Hashing.SHA2
  ( -- ** Usage
    -- $usage

    -- ** Hash
    Hash
  , hashToBinary
  , hashToHexText
  , hashToHexByteString

    -- ** Hashing a single message
  , hashByteString
  , hashText

    -- ** Hashing a multi-parts message
  , Multipart
  , withMultipart
  , updateMultipart
  , finaliseMultipart
  ) where

import Sel.Hashing.SHA2.SHA512

-- $usage
--
-- The SHA-2 family of hashing functions is only provided for interoperability with other applications.
--
-- If you are looking for a generic hash function, do use 'Sel.Hashing'.
--
-- If you are looking to hash passwords or deriving keys from passwords, do use 'Sel.Hashing.Password',
-- as the functions of the SHA-2 family are not suitable for this task.
--
-- Only import this module qualified like this:
--
-- >>> import qualified Sel.Hashing.SHA2 as SHA2
