{-# LANGUAGE NamedFieldPuns #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TypeApplications #-}

-- |
--
-- Module: Sel.SecretKey.AuthenticatedEncryption
-- Description: Authenticated Encryption with Poly1305 MAC and XSalsa20
-- Copyright: (C) Hécate Moonlight 2022
-- License: BSD-3-Clause
-- Maintainer: The Haskell Cryptography Group
-- Portability: GHC only
module Sel.SecretKey.AuthenticatedEncryption
  ( -- ** Introduction
    -- $introduction

    -- ** Usage
    -- $usage
    SecretKey
  , newSecretKey
  , Nonce
  , newNonce
  , Hash
  , encrypt
  , decrypt
  ) where

import Data.ByteString (StrictByteString)
import qualified Data.ByteString.Unsafe as BS
import Foreign (ForeignPtr)
import qualified Foreign
import Foreign.C (CChar, CUChar, CULLong)
import GHC.IO.Handle.Text (memcpy)
import System.IO.Unsafe (unsafeDupablePerformIO)

import Control.Monad (void)
import Data.Word (Word8)
import LibSodium.Bindings.Random (randombytesBuf)
import LibSodium.Bindings.Secretbox (cryptoSecretboxEasy, cryptoSecretboxKeyBytes, cryptoSecretboxKeygen, cryptoSecretboxMACBytes, cryptoSecretboxNonceBytes, cryptoSecretboxOpenEasy)
import Sel.Internal

-- $introduction
-- Authenticated Encryption is the action of encrypting a message using a secret key
-- and a one-time cryptographic number ("nonce"). The resulting ciphertext is accompanied
-- by an authentication tag.
--
-- Encryption is done with the XSalsa20 stream cipher and authentication is done with the
-- Poly1305 MAC hash.

-- $usage
-- TODO

-- |
--
-- @since 0.0.1.0
newtype SecretKey = SecretKey (ForeignPtr CUChar)

-- |
--
-- @since 0.0.1.0
instance Eq SecretKey where
  (SecretKey hk1) == (SecretKey hk2) =
    unsafeDupablePerformIO $
      foreignPtrEq hk1 hk2 cryptoSecretboxKeyBytes

-- |
--
-- @since 0.0.1.0
instance Ord SecretKey where
  compare (SecretKey hk1) (SecretKey hk2) =
    unsafeDupablePerformIO $
      foreignPtrOrd hk1 hk2 cryptoSecretboxKeyBytes

-- |
--
-- @since 0.0.1.0
newtype Nonce = Nonce (ForeignPtr CUChar)

-- |
--
-- @since 0.0.1.0
instance Eq Nonce where
  (Nonce hk1) == (Nonce hk2) =
    unsafeDupablePerformIO $
      foreignPtrEq hk1 hk2 cryptoSecretboxKeyBytes

-- |
--
-- @since 0.0.1.0
instance Ord Nonce where
  compare (Nonce hk1) (Nonce hk2) =
    unsafeDupablePerformIO $
      foreignPtrOrd hk1 hk2 cryptoSecretboxKeyBytes

-- |
--
-- @since 0.0.1.0
newSecretKey :: IO SecretKey
newSecretKey = do
  fPtr <- Foreign.mallocForeignPtrBytes (fromIntegral cryptoSecretboxKeyBytes)
  Foreign.withForeignPtr fPtr $ \ptr ->
    cryptoSecretboxKeygen ptr
  pure $ SecretKey fPtr

-- |
--
-- @since 0.0.1.0
newNonce :: IO Nonce
newNonce = do
  (fPtr :: ForeignPtr CUChar) <- Foreign.mallocForeignPtrBytes (fromIntegral cryptoSecretboxNonceBytes)
  Foreign.withForeignPtr fPtr $ \ptr ->
    randombytesBuf (Foreign.castPtr @CUChar @Word8 ptr) cryptoSecretboxNonceBytes
  pure $ Nonce fPtr

-- |
--
-- @since 0.0.1.0
data Hash = Hash
  { messageLength :: CULLong
  , hashForeignPtr :: ForeignPtr CUChar
  }

-- |
--
-- @since 0.0.1.0
instance Eq Hash where
  (Hash messageLength1 hk1) == (Hash messageLength2 hk2) =
    unsafeDupablePerformIO $ do
      result1 <- foreignPtrEq hk1 hk2 (fromIntegral messageLength1 + cryptoSecretboxMACBytes)
      pure $ (messageLength1 == messageLength2) && result1

-- |
--
-- @since 0.0.1.0
instance Ord Hash where
  compare (Hash messageLength1 hk1) (Hash messageLength2 hk2) =
    unsafeDupablePerformIO $ do
      result1 <- foreignPtrOrd hk1 hk2 (fromIntegral messageLength1 + cryptoSecretboxMACBytes)
      pure $ compare messageLength1 messageLength2 <> result1

encrypt
  :: StrictByteString
  -- ^ Message to encrypt
  -> SecretKey
  -- ^ Secret key generated with 'newSecretKey'
  -> Nonce
  -- ^ One-time use number generated with 'newNonce'
  -> IO Hash
encrypt message (SecretKey secretKeyForeignPtr) (Nonce nonceForeignPtr) =
  BS.unsafeUseAsCStringLen message $ \(cString, cStringLen) -> do
    hashForeignPtr <- Foreign.mallocForeignPtrBytes (cStringLen + fromIntegral cryptoSecretboxMACBytes)
    Foreign.withForeignPtr hashForeignPtr $ \hashPtr ->
      Foreign.withForeignPtr secretKeyForeignPtr $ \secretKeyPtr ->
        Foreign.withForeignPtr nonceForeignPtr $ \noncePtr -> do
          void $
            cryptoSecretboxEasy
              hashPtr
              (Foreign.castPtr @CChar @CUChar cString)
              (fromIntegral @Int @CULLong cStringLen)
              noncePtr
              secretKeyPtr
    pure $ Hash (fromIntegral @Int @CULLong cStringLen) hashForeignPtr

decrypt
  :: Hash
  -- ^ Encrypted message
  -> SecretKey
  -- ^ Secret key used for encrypting the original message
  -> Nonce
  -- ^ Nonce used for encrypting the original message
  -> Maybe StrictByteString
decrypt Hash{messageLength, hashForeignPtr} (SecretKey secretKeyForeignPtr) (Nonce nonceForeignPtr) = unsafeDupablePerformIO $ do
  messagePtr <- Foreign.mallocBytes (fromIntegral @CULLong @Int messageLength)
  Foreign.withForeignPtr hashForeignPtr $ \hashPtr ->
    Foreign.withForeignPtr secretKeyForeignPtr $ \secretKeyPtr ->
      Foreign.withForeignPtr nonceForeignPtr $ \noncePtr -> do
        result <-
          cryptoSecretboxOpenEasy
            messagePtr
            hashPtr
            (messageLength + fromIntegral cryptoSecretboxMACBytes)
            noncePtr
            secretKeyPtr
        case result of
          (-1) -> pure Nothing
          _ -> do
            bsPtr <- Foreign.mallocBytes (fromIntegral messageLength)
            memcpy bsPtr (Foreign.castPtr messagePtr) (fromIntegral messageLength)
            Just <$> BS.unsafePackMallocCStringLen (Foreign.castPtr @CChar bsPtr, fromIntegral messageLength)
