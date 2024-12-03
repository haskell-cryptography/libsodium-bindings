{-# LANGUAGE DerivingStrategies #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE ImportQualifiedPost #-}
{-# LANGUAGE KindSignatures #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TypeApplications #-}

-- |
-- Module      : Sel.ByteString.Codec
-- Description : Base16 codecs for cryptographic key material
-- Copyright   : (c) Jack Henahan, 2024
-- License     : BSD-3-Clause
-- Maintainer  : The Haskell Cryptography Group
-- Portability : GHC only
--
-- This module provides type classes and utility functions for working
-- with hexadecimal encoded ('Base16') cryptographic key material.
module Sel.ByteString.Codec
  ( -- * Base 16 codecs for key material

    -- ** Encoding key material to hexadecimal bytes
    HexEncode (..) -- ^ @since 0.0.3.0
  , encodeHexByteString -- ^ @since 0.0.3.0

    -- ** Decoding hexadecimal bytes to key material
  , HexDecode (..) -- ^ @since 0.0.3.0
  , decodeHexByteString -- ^ @since 0.0.3.0

    -- ** Deriving instances
  , HexBytes (..) -- ^ @since 0.0.3.0
  )
where

import Control.Monad ((>=>))
import Data.Base16.Types (Base16)
import Data.Base16.Types qualified as Base16
import Data.ByteString (StrictByteString)
import Data.ByteString.Base16 qualified as Base16
import Data.ByteString.Internal qualified as ByteString
import Data.Coerce (coerce)
import Data.Kind (Type)
import Data.Text qualified as Text
import Data.Word (Word8)
import Foreign qualified
import Foreign.C (CUChar)
import Sel.ByteString.Codec.KeyMaterialDecodeError
  ( KeyMaterialDecodeError (..)
  , validKeyMaterialHexBytes
  )
import Sel.ByteString.Codec.KeyPointer
  ( KeyCoerce
  , KeyPointer (..)
  , keyPointerLength
  )
import Text.Read

-- | Convert key material to a 'Base16' 'StrictByteString' to enable
-- serialization, transmission, display, etc.
--
-- @since 0.0.3.0
class HexEncode k where
  -- | Convert key material to a 'Base16' 'StrictByteString'.
  --
  -- @since 0.0.3.0
  encodeHexBytes :: k -> Base16 StrictByteString

-- | Convert key material to a hexadecimal-encoded 'StrictByteString'.
--
-- @since 0.0.3.0
encodeHexByteString :: HexEncode k => k -> StrictByteString
encodeHexByteString = Base16.extractBase16 . encodeHexBytes

-- | Derive a hexadecimal encoder for key material from its pointer
-- size to enable serialization for transmission.
--
-- @since 0.0.3.0
instance KeyCoerce a => HexEncode (KeyPointer a cmp) where
  encodeHexBytes a =
    Base16.encodeBase16' $
      ByteString.fromForeignPtr0
        (Foreign.castForeignPtr @CUChar @Word8 (coerce a))
        (keyPointerLength @a)

-- | Decode a 'Base16' 'StrictByteString' to key material to enable
-- deserialization from external sources.
--
-- @since 0.0.3.0
class HexDecode k where
  -- | Decode a 'Base16' 'StrictByteString' to key material, yielding
  -- a 'KeyMaterialDecodeError' on failure.
  --
  -- @since 0.0.3.0
  decodeHexBytes :: Base16 StrictByteString -> Either KeyMaterialDecodeError k

-- | Decode a hexadecimal-encoded 'StrictByteString' to key material,
-- yielding a 'KeyMaterialDecodeError' on failure.
--
-- @since 0.0.3.0
decodeHexByteString :: HexDecode k => StrictByteString -> Either KeyMaterialDecodeError k
decodeHexByteString = validKeyMaterialHexBytes >=> decodeHexBytes

-- | A wrapper to enable deriving instances from the hexadecimal
-- representation of the underlying value.
--
-- === Example
--
-- @
-- newtype SomeKeyMaterial = SomeKeyMaterial (ForeignPtr CUChar)
--   deriving (Show) via (HexBytes SomeKeyMaterial)
--   deriving (Eq, Ord, HexEncode) via (KeyPointer SomeKeyMaterial)
--
-- instance KeyPointerSize SomeKeyMaterial where
--   keyPointerSize :: CSize
--   keyPointerSize = {- get your size from the FFI bindings -}
-- @
--
-- @since 0.0.3.0
newtype HexBytes (a :: Type) = HexBytes a
  deriving newtype
    ( HexEncode
      -- ^ @since 0.0.3.0
    , HexDecode
      -- ^ @since 0.0.3.0
    )

-- | Derive 'Show' via the hexadecimal representation of some key
-- material.
--
-- @since 0.0.3.0
instance HexEncode a => Show (HexBytes a) where
  show = ByteString.unpackChars . encodeHexByteString

-- | Derive 'Read' via the hexadecimal representation of some key
-- material.
--
-- @since 0.0.3.0
instance HexDecode a => Read (HexBytes a) where
  readPrec = do
    str <- look
    let bs = ByteString.packChars str
        decoded = decodeHexByteString @a bs
    case decoded of
      Right hex -> pure $ HexBytes hex
      Left materialError -> fail $ case materialError of
        ByteLengthMismatch required input ->
          mconcat
            [ "Input "
            , str
            , " has length "
            , show input
            , " but the decoder demands "
            , show required
            ]
        DecodingFailure message ->
          mconcat
            [ "Failed to decode "
            , str
            , " as hexadecimal: "
            , Text.unpack message
            ]
