{-# LANGUAGE InstanceSigs #-}

-- |
--
-- Module: Sel.Hashing
-- Description: Hashing with the BLAKE2b algorithm
-- Copyright: (C) Hécate Moonlight 2022
-- License: BSD-3-Clause
-- Maintainer: The Haskell Cryptography Group
-- Portability: GHC only
module Sel.Hashing
  ( -- ** Introduction
    -- $introduction

    -- ** Operations
    HashKey
  , newHashKey
  , Hash
  , hashByteString
  , hashToHexText
  , hashToHexByteString
  , hashToBinary
  )
where

import Control.Monad (void)
import Data.ByteString (StrictByteString)
import qualified Data.ByteString.Base16 as Base16
import qualified Data.ByteString.Internal as BS

import Data.ByteString.Unsafe (unsafeUseAsCStringLen)
import Data.Text (Text)
import Data.Text.Display
import qualified Data.Text.Lazy.Builder as Builder
import Foreign (Ptr)
import qualified Foreign
import Foreign.C (CSize, CUChar)
import Foreign.ForeignPtr
import Foreign.Storable
import LibSodium.Bindings.GenericHashing (cryptoGenericHash, cryptoGenericHashBytes, cryptoGenericHashKeyBytes, cryptoGenericHashKeyGen)
import Sel.Internal
import System.IO.Unsafe (unsafeDupablePerformIO)

-- $introduction
--
-- This API computes a fixed-length fingerprint for an arbitrarily long message.
-- It is backed by the [BLAKE2b](https://en.wikipedia.org/wiki/BLAKE_\(hash_function\)) algorithm.
--
-- Sample use cases:
--
--   * File integrity checking
--   * Creating unique identifiers to index arbitrarily long data
--
-- __⚠️ Do not use this module to hash passwords! ⚠️__ Please use the "Sel.Hashing.Password" module instead.
--
-- If you need to deviate from the defaults enforced by this module,
-- please use the underlying bindings at "LibSodium.Bindings.GenericHashing".

-- | The 'HashKey' is used to produce distinct fingerprints for the same message.
-- It is optional to use, and 'hashByteString' will always produce the same fingerprint
-- for the same message if a 'HashKey' is not given. This behaviour is similar to
-- MD5 and SHA-1 functions, for which 'hashByteString' is a faster and more secure alternative.
--
-- Create a new 'HashKey' with 'newHashKey'.
--
-- @since 0.0.1.0
newtype HashKey = HashKey (ForeignPtr CUChar)

instance Eq HashKey where
  (HashKey hk1) == (HashKey hk2) =
    unsafeDupablePerformIO $
      foreignPtrEq hk1 hk2 cryptoGenericHashKeyBytes

instance Ord HashKey where
  compare (HashKey hk1) (HashKey hk2) =
    unsafeDupablePerformIO $
      foreignPtrOrd hk1 hk2 cryptoGenericHashKeyBytes

-- | Create a new 'HashKey' of size 'cryptoGenericHashKeyBytes'.
--
-- @since 0.0.1.0
newHashKey :: IO HashKey
newHashKey = do
  fPtr <- Foreign.mallocForeignPtrBytes (fromIntegral cryptoGenericHashKeyBytes)
  Foreign.withForeignPtr fPtr $ \ptr ->
    cryptoGenericHashKeyGen ptr
  pure $ HashKey fPtr

-- | The fingerprint computed by @hashByteString@.
-- It is produced by the BLAKE2b algorithm, and is
-- of size 'cryptoGenericHashBytes', as recommended.
--
-- You can produce a human-readable string representation
-- of a 'Hash' by using the @display@ function.
--
-- @since 0.0.1.0
newtype Hash = Hash (ForeignPtr CUChar)

instance Eq Hash where
  (Hash h1) == (Hash h2) =
    unsafeDupablePerformIO $
      foreignPtrEq h1 h2 cryptoGenericHashBytes

instance Ord Hash where
  compare (Hash h1) (Hash h2) =
    unsafeDupablePerformIO $
      foreignPtrOrd h1 h2 cryptoGenericHashBytes

instance Storable Hash where
  sizeOf :: Hash -> Int
  sizeOf _ = fromIntegral cryptoGenericHashBytes

  --  Aligned on the size of 'cryptoGenericHashBytes'
  alignment :: Hash -> Int
  alignment _ = 32

  poke :: Ptr Hash -> Hash -> IO ()
  poke ptr (Hash hashForeignPtr) =
    Foreign.withForeignPtr hashForeignPtr $ \hashPtr ->
      Foreign.copyArray (Foreign.castPtr ptr) hashPtr (fromIntegral cryptoGenericHashKeyBytes)

  peek :: Ptr Hash -> IO Hash
  peek ptr = do
    hashfPtr <- Foreign.mallocForeignPtrBytes (fromIntegral cryptoGenericHashKeyBytes)
    Foreign.withForeignPtr hashfPtr $ \hashPtr ->
      Foreign.copyArray hashPtr (Foreign.castPtr ptr) (fromIntegral cryptoGenericHashKeyBytes)
    pure $ Hash hashfPtr

instance Display Hash where
  displayBuilder = Builder.fromText . hashToHexText

instance Show Hash where
  show = BS.unpackChars . hashToHexByteString

-- | Hash a 'StrictByteString' with the BLAKE2b algorithm, and an optional key.
--
-- Without a 'HashKey', hashing the same data twice will give the same result.
--
-- @since 0.0.1.0
hashByteString :: Maybe HashKey -> StrictByteString -> IO Hash
hashByteString mHashKey bytestring =
  case mHashKey of
    Just (HashKey fPtr) ->
      Foreign.withForeignPtr fPtr $ \keyPtr ->
        doHashByteString keyPtr cryptoGenericHashKeyBytes
    Nothing ->
      doHashByteString Foreign.nullPtr 0
  where
    doHashByteString :: Ptr a -> CSize -> IO Hash
    doHashByteString keyPtr keyLength =
      unsafeUseAsCStringLen bytestring $ \(cString, cStringLen) -> do
        hashForeignPtr <- Foreign.mallocForeignPtrBytes (fromIntegral cryptoGenericHashBytes)
        Foreign.withForeignPtr hashForeignPtr $ \hashPtr -> do
          void $
            cryptoGenericHash
              hashPtr
              cryptoGenericHashBytes
              (Foreign.castPtr cString :: Ptr CUChar)
              (fromIntegral cStringLen)
              (Foreign.castPtr keyPtr :: Ptr CUChar)
              keyLength
        pure $ Hash hashForeignPtr

-- | Convert a 'Hash' to a strict hexadecimal 'Text'.
--
-- @since 0.0.1.0
hashToHexText :: Hash -> Text
hashToHexText = Base16.encodeBase16 . hashToBinary

-- | Convert a 'Hash' to a strict, hexadecimal-encoded 'StrictByteString'.
--
-- @since 0.0.1.0
hashToHexByteString :: Hash -> StrictByteString
hashToHexByteString = Base16.encodeBase16' . hashToBinary

-- | Convert a 'Hash' to a strict binary 'StrictByteString'.
--
-- @since 0.0.1.0
hashToBinary :: Hash -> StrictByteString
hashToBinary (Hash fPtr) =
  BS.fromForeignPtr (Foreign.castForeignPtr fPtr) 0 hashBytesSize
  where
    hashBytesSize = fromIntegral cryptoGenericHashBytes
