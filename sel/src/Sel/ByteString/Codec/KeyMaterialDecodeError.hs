{-# LANGUAGE AllowAmbiguousTypes #-}
{-# LANGUAGE DeriveAnyClass #-}
{-# LANGUAGE DerivingVia #-}
{-# LANGUAGE ImportQualifiedPost #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TypeApplications #-}
{-# LANGUAGE ViewPatterns #-}

-- |
-- Module      : Sel.ByteString.Codec.KeyMaterialDecodeError
-- Description : Decoding errors for cryptographic key material
-- Copyright   : (c) Jack Henahan, 2024
-- License     : BSD-3-Clause
-- Maintainer  : The Haskell Cryptography Group
-- Portability : GHC only
--
-- This module models common error cases when decoding cryptographic
-- key material and provides utilities for validating key material
-- during decoding.
module Sel.ByteString.Codec.KeyMaterialDecodeError
  ( KeyMaterialDecodeError (..)
  , RequiredLength (..)
  , InputLength (..)
  , validKeyMaterialHexBytes
  , validKeyMaterialLength
  ) where

import Control.Exception (Exception)
import Data.Base16.Types (Base16)
import Data.Bifunctor (bimap)
import Data.ByteString (StrictByteString)
import Data.ByteString qualified as ByteString
import Data.ByteString.Base16 qualified as Base16
import Data.Coerce (coerce)
import Data.Text (Text)
import Data.Text.Display (Display, ShowInstance (..))
import Sel.ByteString.Codec.KeyPointer (KeyPointerSize, keyPointerLength)

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

-- | Decode a hexadecimal-encoded 'StrictByteString' to a 'Base16'
-- 'StrictByteString'.
--
-- @since 0.0.3.0
validKeyMaterialHexBytes :: StrictByteString -> Either KeyMaterialDecodeError (Base16 StrictByteString)
validKeyMaterialHexBytes = bimap DecodingFailure Base16.encodeBase16' . Base16.decodeBase16Untyped

-- | Ensure the provided bytes match the expected length of the target
-- pointer.
--
-- @since 0.0.3.0
validKeyMaterialLength
  :: forall a
   . KeyPointerSize a
  => StrictByteString
  -> Either KeyMaterialDecodeError StrictByteString
validKeyMaterialLength bs@(ByteString.length -> inputLength) =
  guardEither
    (requiredLength == inputLength)
    (ByteLengthMismatch (coerce requiredLength) (coerce inputLength))
    bs
  where
    requiredLength = keyPointerLength @a

guardEither :: Bool -> a -> b -> Either a b
guardEither p f t = if p then Right t else Left f
