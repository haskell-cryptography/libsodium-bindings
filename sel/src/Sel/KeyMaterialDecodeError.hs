{-# LANGUAGE DeriveAnyClass #-}
{-# LANGUAGE DerivingVia #-}
{-# LANGUAGE ImportQualifiedPost #-}
{-# LANGUAGE ViewPatterns #-}

-- |
-- Module      : Sel.KeyMaterialDecodeError
-- Description : Key material utilities
-- Copyright   : (c) Jack Henahan, 2024
-- License     : BSD-3-Clause
-- Maintainer  : The Haskell Cryptography Group
-- Portability : GHC only
module Sel.KeyMaterialDecodeError
  ( -- * Key material utilities
    KeyMaterialDecodeError (..)
  , RequiredLength (..)
  , InputLength (..)
  , validKeyMaterial
  )
where

import Control.Exception (Exception)
import Data.Bifunctor (first)
import Data.ByteString (StrictByteString)
import Data.ByteString qualified as ByteString
import Data.ByteString.Base16 qualified as Base16
import Data.Coerce (coerce)
import Data.Text (Text)
import Data.Text.Display (Display, ShowInstance (..))
import Foreign.C (CSize (..))

-- | Errors arising from decoding key material from bytes.
--
-- @since 0.0.3.0
data KeyMaterialDecodeError
  = -- | Input length does not match the length required for the target pointer.
    --
    -- @since 0.0.3.0
    ByteLengthMismatch RequiredLength InputLength
  | -- | Input bytes did not decode to hexadecimal.
    --
    -- @since 0.0.3.0
    DecodingFailure Text
  deriving stock
    ( Show
      -- ^ @since 0.0.3.0
    , Eq
      -- ^ @since 0.0.3.0
    )
  deriving
    ( Display
      -- ^ @since 0.0.3.0
    )
    via (ShowInstance KeyMaterialDecodeError)
  deriving anyclass
    ( Exception
      -- ^ @since 0.0.3.0
    )

-- | The length of the target pointer for some key material.
--
-- @since 0.0.3.0
newtype RequiredLength = RequiredLength Int
  deriving stock
    ( Show
      -- ^ @since 0.0.3.0
    , Eq
      -- ^ @since 0.0.3.0
    )

-- | The length of some input bytes.
--
-- @since 0.0.3.0
newtype InputLength = InputLength Int
  deriving stock
    ( Show
      -- ^ @since 0.0.3.0
    , Eq
      -- ^ @since 0.0.3.0
    )

-- | Attempt to decode a hexadecimal-encoded 'StrictByteString' with an expected length.
--
-- @since 0.0.3.0
validKeyMaterial :: CSize -> StrictByteString -> Either KeyMaterialDecodeError StrictByteString
validKeyMaterial (fromIntegral -> requiredLength) bytes = do
  decoded@(ByteString.length -> inputLength) <-
    first DecodingFailure (Base16.decodeBase16Untyped bytes)
  if requiredLength == inputLength
    then Right decoded
    else Left $ ByteLengthMismatch (coerce requiredLength) (coerce inputLength)
