{-# LANGUAGE DerivingStrategies #-}
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE ImportQualifiedPost #-}
{-# LANGUAGE KindSignatures #-}
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
-- This module provides utility functions for working with
-- hexadecimal-encoded ('Base16') cryptographic key material.
module Sel.ByteString.Codec
  ( -- * Base 16 codecs for key material

    -- ** Encoding key material to hexadecimal bytes
    encodeHexByteString'
  , encodeHexByteString

    -- ** Decoding hexadecimal bytes to key material
  , decodeHexByteString'
  , decodeHexByteString

    -- ** Defining instances
  , showHexEncoding
  )
where

import Control.Monad ((>=>))
import Data.Base16.Types (Base16)
import Data.Base16.Types qualified as Base16
import Data.ByteString (StrictByteString)
import Data.ByteString.Base16 qualified as Base16
import Data.ByteString.Internal qualified as ByteString
import Data.Coerce (coerce)
import Data.Word (Word8)
import Foreign qualified
import Foreign.C (CUChar)
import Sel.ByteString.Codec.KeyMaterialDecodeError
  ( KeyMaterialDecodeError (..)
  , validKeyMaterialHexBytes
  )
import Sel.ByteString.Codec.KeyPointer
  ( KeyCoerce
  , keyPointerLength
  )
import Sel.Key

-- | Encode key material with a known pointer size by copying and
-- encoding the bytes.
--
-- @since 0.0.3.0
copyingEncoder :: forall a. KeyCoerce a => a -> Base16 StrictByteString
copyingEncoder k =
  Base16.encodeBase16' $
    ByteString.fromForeignPtr0
      (Foreign.castForeignPtr @CUChar @Word8 (coerce k))
      (keyPointerLength @a)

-- | Convert key material to a hexadecimal-encoded 'StrictByteString'
-- using a provided hexadecimal encoder.
--
-- @since 0.0.3.0
encodeHexByteString' :: (k -> Base16 StrictByteString) -> k -> StrictByteString
encodeHexByteString' encoder = Base16.extractBase16 . encoder

-- | Convert key material to a hexadecimal-encoded 'StrictByteString'
-- using the default copying encoder.
--
-- @since 0.0.3.0
encodeHexByteString :: KeyCoerce k => k -> StrictByteString
encodeHexByteString = encodeHexByteString' copyingEncoder

-- | Derive 'Show' via the hexadecimal representation of some key
-- material, using the default copying encoder.
--
-- @since 0.0.3.0
showHexEncoding :: KeyCoerce k => k -> String
showHexEncoding = ByteString.unpackChars . encodeHexByteString

-- | Decode key material with a known pointer size by copying the
-- bytes into a fresh key.
--
-- @since 0.0.3.0
copyingDecoder :: KeyCoerce k => Base16 StrictByteString -> Either KeyMaterialDecodeError k
copyingDecoder = toKey . Base16.decodeBase16

-- | Decode a hexadecimal-encoded 'StrictByteString' to key material
-- using a provided hexadecimal decoder, yielding a
-- 'KeyMaterialDecodeError' on failure.
--
-- @since 0.0.3.0
decodeHexByteString'
  :: (Base16 StrictByteString -> Either KeyMaterialDecodeError k)
  -> StrictByteString
  -> Either KeyMaterialDecodeError k
decodeHexByteString' decoder = validKeyMaterialHexBytes >=> decoder

-- | Decode a hexadecimal-encoded 'StrictByteString' to key material
-- using the default copying decoder, yielding a
-- 'KeyMaterialDecodeError' on failure.
--
-- @since 0.0.3.0
decodeHexByteString :: KeyCoerce k => StrictByteString -> Either KeyMaterialDecodeError k
decodeHexByteString = decodeHexByteString' copyingDecoder
