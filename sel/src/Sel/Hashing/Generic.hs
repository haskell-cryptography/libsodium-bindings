{-# LANGUAGE InstanceSigs #-}

-- |
--
-- Module: Sel.Hashing.Generic
-- Description: Fingerprint hashing with the BLAKE2b algorithm
-- Copyright: (C) Hécate Moonlight 2022
-- License: BSD-3-Clause
-- Maintainer: The Haskell Cryptography Group
-- Portability: GHC only
module Sel.Hashing.Generic
  ( -- * Introduction
    -- $introduction

    -- * Operations
    HashKey
  , newHashKey
  , Hash
  , hashByteString
  , hashToText
  , hashToByteString
  , hashToBinary
  )
where

import Control.Monad (void)
import Data.ByteString (ByteString)
import qualified Data.ByteString.Base16 as Base16
import qualified Data.ByteString.Internal as BS

-- import qualified Data.ByteString.Unsafe as BS
import Data.ByteString.Unsafe (unsafeUseAsCStringLen)
import Data.Text (Text)
import Data.Text.Display
import qualified Data.Text.Lazy.Builder as Builder
import Foreign (ForeignPtr, Ptr)
import qualified Foreign
import Foreign.C (CSize, CUChar)
import Foreign.Storable
import LibSodium.Bindings.GenericHashing (cryptoGenericHash, cryptoGenericHashBytes, cryptoGenericHashKeyBytes, cryptoGenericHashKeyGen)

-- $introduction
--
-- This API computes a fixed-length fingerprint for an arbitrarily long message.
-- It is backed by the BLAKE2b algorithm.
--
-- Sample use cases:
--
--   * File integrity checking
--   * Creating unique identifiers to index arbitrarily long data
--
-- __⚠️ Do not use this module to hash passwords! ⚠️__
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

-- | Create a new 'HashKey' of size 'cryptoGenericHashKeyBytes'.
--
-- @since 0.0.1.0
newHashKey :: IO HashKey
newHashKey = do
  fPtr <- Foreign.mallocForeignPtrBytes (fromIntegral cryptoGenericHashKeyBytes)
  Foreign.withForeignPtr fPtr $ \ptr ->
    cryptoGenericHashKeyGen ptr
  pure $ HashKey fPtr

-- | The fingerprint computed by `hashByteString`.
-- It is produced by the BLAKE2b algorithm, and is
-- of size 'cryptoGenericHashBytes', as recommended.
--
-- You can produce a human-readable string representation
-- of a 'Hash' by using the `display` function.
--
-- @since 0.0.1.0
newtype Hash = Hash (ForeignPtr CUChar)

instance Storable Hash where
  sizeOf :: Hash -> Int
  sizeOf _ = fromIntegral cryptoGenericHashBytes

  alignment :: Hash -> Int
  alignment _ = sizeOf (undefined :: CSize)

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
  displayBuilder = Builder.fromText . hashToText

-- | Hash a 'ByteString' with the BLAKE2b algorithm, and an optional key.
--
-- Without a 'HashKey', hashing the same data twice will give the same result.
--
-- @since 0.0.1.0
hashByteString :: Maybe HashKey -> ByteString -> IO Hash
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
              (Foreign.castPtr keyPtr)
              keyLength
        pure $ Hash hashForeignPtr

-- | Convert a 'Hash' to a strict hexadecimal 'Text'.
--
-- @since 0.0.1.0
hashToText :: Hash -> Text
hashToText = Base16.encodeBase16 . hashToBinary

-- | Convert a 'Hash' to a strict, hexadecimal-encoded 'ByteString'.
--
-- @since 0.0.1.0
hashToByteString :: Hash -> ByteString
hashToByteString = Base16.encodeBase16' . hashToBinary

-- | Convert a 'Hash' to a strict binary 'ByteString'.
--
-- @since 0.0.1.0
hashToBinary :: Hash -> ByteString
hashToBinary (Hash fPtr) =
  BS.fromForeignPtr (Foreign.castForeignPtr fPtr) 0 hashBytesSize
  where
    hashBytesSize = fromIntegral cryptoGenericHashBytes
