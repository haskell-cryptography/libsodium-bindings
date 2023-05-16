{-# LANGUAGE InstanceSigs #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TypeApplications #-}

-- |
-- Module: Sel.Hashing.SHA2.SHA256
-- Description: SHA-256 hashing
-- Copyright: (C) Hécate Moonlight 2022
-- License: BSD-3-Clause
-- Maintainer: The Haskell Cryptography Group
-- Portability: GHC only
module Sel.Hashing.SHA2.SHA256
  ( -- ** Usage
    -- $usage
    Hash

    -- ** Hashing a single message
  , hashByteString
  , hashText

    -- ** Displaying
  , hashToBinary
  , hashToHexText
  , hashToHexByteString

    -- ** Hashing a multi-parts message
  , Multipart
  , withMultipart
  , updateMultipart
  , finaliseMultipart
  ) where

import Control.Monad (void)
import Data.ByteString (StrictByteString)
import qualified Data.ByteString.Base16 as Base16
import qualified Data.ByteString.Internal as BS
import qualified Data.ByteString.Unsafe as BS
import Data.Text (Text)
import Data.Text.Display (Display (..))
import qualified Data.Text.Encoding as Text
import qualified Data.Text.Internal.Builder as Builder
import Foreign (ForeignPtr, Ptr, Storable)
import qualified Foreign
import Foreign.C (CChar, CSize, CUChar, CULLong)
import LibSodium.Bindings.SHA2 (CryptoHashSHA256State, cryptoHashSHA256, cryptoHashSHA256Bytes, cryptoHashSHA256Final, cryptoHashSHA256Init, cryptoHashSHA256StateBytes, cryptoHashSHA256Update)
import System.IO.Unsafe (unsafeDupablePerformIO)

import Sel.Internal

-- $usage
--
-- The SHA-2 family of hashing functions is only provided for interoperability with other applications.
--
-- If you are looking for a generic hash function, do use 'Sel.Hashing.Generic'.
--
-- If you are looking to hash passwords or deriving keys from passwords, do use 'Sel.Hashing.Password',
-- as the functions of the SHA-2 family are not suitable for this task.
--
-- Only import this module qualified like this:
--
-- >>> import qualified Sel.Hashing.SHA2.SHA256 as SHA256

-- | A hashed value from the SHA-256 algorithm.
--
-- @since 0.0.1.0
newtype Hash = Hash (ForeignPtr CUChar)

-- |
--
-- @since 0.0.1.0
instance Eq Hash where
  (Hash h1) == (Hash h2) =
    unsafeDupablePerformIO $
      foreignPtrEq h1 h2 cryptoHashSHA256Bytes

-- |
--
-- @since 0.0.1.0
instance Ord Hash where
  compare (Hash h1) (Hash h2) =
    unsafeDupablePerformIO $
      foreignPtrOrd h1 h2 cryptoHashSHA256Bytes

-- |
--
-- @since 0.0.1.0
instance Storable Hash where
  sizeOf :: Hash -> Int
  sizeOf _ = fromIntegral cryptoHashSHA256Bytes

  --  Aligned on the size of 'cryptoHashSHA256Bytes'
  alignment :: Hash -> Int
  alignment _ = 32

  poke :: Ptr Hash -> Hash -> IO ()
  poke ptr (Hash hashForeignPtr) =
    Foreign.withForeignPtr hashForeignPtr $ \hashPtr ->
      Foreign.copyArray (Foreign.castPtr ptr) hashPtr (fromIntegral cryptoHashSHA256Bytes)

  peek :: Ptr Hash -> IO Hash
  peek ptr = do
    hashfPtr <- Foreign.mallocForeignPtrBytes (fromIntegral cryptoHashSHA256Bytes)
    Foreign.withForeignPtr hashfPtr $ \hashPtr ->
      Foreign.copyArray hashPtr (Foreign.castPtr ptr) (fromIntegral cryptoHashSHA256Bytes)
    pure $ Hash hashfPtr

-- |
--
-- @since 0.0.1.0
instance Display Hash where
  displayBuilder = Builder.fromText . hashToHexText

-- |
--
-- @since 0.0.1.0
instance Show Hash where
  show = BS.unpackChars . hashToHexByteString

-- | Hash a 'StrictByteString' with the SHA-256 algorithm.
--
-- @since 0.0.1.0
hashByteString :: StrictByteString -> IO Hash
hashByteString bytestring =
  BS.unsafeUseAsCStringLen bytestring $ \(cString, cStringLen) -> do
    hashForeignPtr <- Foreign.mallocForeignPtrBytes (fromIntegral cryptoHashSHA256Bytes)
    Foreign.withForeignPtr hashForeignPtr $ \hashPtr ->
      void $
        cryptoHashSHA256
          hashPtr
          (Foreign.castPtr cString :: Ptr CUChar)
          (fromIntegral @Int @CULLong cStringLen)
    pure $ Hash hashForeignPtr

-- | Hash a UTF8-encoded strict 'Text' with the SHA-256 algorithm.
--
-- @since 0.0.1.0
hashText :: Text -> IO Hash
hashText text = hashByteString (Text.encodeUtf8 text)

-- == Displaying

-- | Convert a 'Hash' to a strict hexadecimal 'Text'.
--
-- @since 0.0.1.0
hashToHexText :: Hash -> Text
hashToHexText = Text.decodeUtf8 . hashToBinary

-- | Convert a 'Hash' to a strict, hexadecimal-encoded 'StrictByteString'.
--
-- @since 0.0.1.0
hashToHexByteString :: Hash -> StrictByteString
hashToHexByteString = Base16.encodeBase16' . hashToBinary

-- | Convert a 'Hash' to a binary 'StrictByteString'.
--
-- @since 0.0.1.0
hashToBinary :: Hash -> StrictByteString
hashToBinary (Hash fPtr) =
  BS.fromForeignPtr
    (Foreign.castForeignPtr fPtr)
    0
    (fromIntegral @CSize @Int cryptoHashSHA256Bytes)

-- ** Hashing a multi-parts message
newtype Multipart = Multipart (Ptr CryptoHashSHA256State)

withMultipart :: forall a. (Multipart -> IO a) -> IO a
withMultipart action = do
  allocateWith cryptoHashSHA256StateBytes $ \statePtr -> do
    void $ cryptoHashSHA256Init statePtr
    action (Multipart statePtr)

updateMultipart :: Multipart -> StrictByteString -> IO ()
updateMultipart (Multipart statePtr) message = do
  BS.unsafeUseAsCStringLen message $ \(cString, cStringLen) -> do
    let messagePtr = Foreign.castPtr @CChar @CUChar cString
    let messageLen = fromIntegral @Int @CULLong cStringLen
    void $
      cryptoHashSHA256Update
        statePtr
        messagePtr
        messageLen

finaliseMultipart :: Multipart -> IO Hash
finaliseMultipart (Multipart statePtr) = do
  hashForeignPtr <- Foreign.mallocForeignPtrBytes (fromIntegral cryptoHashSHA256Bytes)
  Foreign.withForeignPtr hashForeignPtr $ \(hashPtr :: Ptr CUChar) ->
    void $
      cryptoHashSHA256Final
        statePtr
        hashPtr
  pure $ Hash hashForeignPtr
