{-# LANGUAGE DataKinds #-}
{-# LANGUAGE DerivingVia #-}
{-# LANGUAGE NamedFieldPuns #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TypeApplications #-}

-- |
--
-- Module: Sel.SecretKey.Cipher
-- Description: Authenticated Encryption with Poly1305 MAC and XSalsa20
-- Copyright: (C) Hécate Moonlight 2022
-- License: BSD-3-Clause
-- Maintainer: The Haskell Cryptography Group
-- Portability: GHC only
module Sel.SecretKey.Cipher
  ( -- ** Introduction
    -- $introduction

    -- ** Usage
    -- $usage

    -- ** Secret Key
    SecretKey
  , newSecretKey
  , secretKeyFromByteString
  , unsafeSecretKeyToHexByteString
  , newSecretKeyWith
  , freeSecretKey

    -- ** Nonce
  , Nonce
  , nonceFromByteString
  , nonceToHexByteString

    -- ** Hash
  , Hash
  , hashFromByteString
  , hashToBinary
  , hashToHexByteString
  , hashToHexText

    -- ** Encryption and Decryption
  , encrypt
  , decrypt
  ) where

import Control.Monad (void, when)
import Data.ByteString (StrictByteString)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Base16 as Base16
import qualified Data.ByteString.Internal as BS
import qualified Data.ByteString.Unsafe as BS
import Data.Text (Text)
import Data.Text.Display (Display (displayBuilder), OpaqueInstance (..), ShowInstance (..))
import qualified Data.Text.Lazy.Builder as Builder
import Data.Word (Word8)
import Foreign (ForeignPtr)
import qualified Foreign
import Foreign.C (CChar, CSize, CUChar, CULLong, throwErrno)
import GHC.IO.Handle.Text (memcpy)
import System.IO.Unsafe (unsafeDupablePerformIO)

import LibSodium.Bindings.Random (randombytesBuf)
import LibSodium.Bindings.Secretbox (cryptoSecretboxEasy, cryptoSecretboxKeyBytes, cryptoSecretboxKeygen, cryptoSecretboxMACBytes, cryptoSecretboxNonceBytes, cryptoSecretboxOpenEasy)
import LibSodium.Bindings.SecureMemory
import Sel.Internal

-- $introduction
-- "Authenticated Encryption" uses a secret key along with a single-use number
-- called a "nonce" to encrypt a message.
-- The resulting hash is accompanied by an authentication tag.
--
-- Encryption is done with the XSalsa20 stream cipher and authentication is done with the
-- Poly1305 MAC hash.

-- $usage
--
-- > import qualified Sel.SecretKey.Cipher as Cipher
-- >
-- > main = do
-- >   -- We get the secretKey from the other party or with 'newSecretKey'.
-- >   -- We get the nonce from the other party with the message, or with 'encrypt' and our own message.
-- >   -- Do not reuse a nonce with the same secret key!
-- >   (nonce, encryptedMessage) <- Cipher.encrypt "hello hello" secretKey
-- >   let result = Cipher.decrypt encryptedMessage secretKey nonce
-- >   print result
-- >   -- "Just \"hello hello\""

-- | A secret key of size 'cryptoSecretboxKeyBytes'.
--
-- @since 0.0.1.0
newtype SecretKey = SecretKey (ForeignPtr CUChar)
  deriving
    ( Display
      -- ^ @since 0.0.1.0
      -- > display secretKey == "[REDACTED]"
    )
    via (OpaqueInstance "[REDACTED]" SecretKey)

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

-- | > show secretKey == "[REDACTED]"
--
-- @since 0.0.1.0
instance Show SecretKey where
  show _ = "[REDACTED]"

-- | Generate a new random secret key.
--
-- @since 0.0.1.0
newSecretKey :: IO SecretKey
newSecretKey = newSecretKeyWith cryptoSecretboxKeygen

-- | Create a 'SecretKey' from a binary 'StrictByteString' that you have obtained on your own,
-- usually from the network or disk.
--
-- @since 0.0.1.0
secretKeyFromByteString :: StrictByteString -> Maybe SecretKey
secretKeyFromByteString bytestring =
  if BS.length bytestring < fromIntegral cryptoSecretboxKeyBytes
    then Nothing
    else unsafeDupablePerformIO $
      BS.unsafeUseAsCStringLen bytestring $ \(outsideSecretKeyPtr, _) ->
        fmap Just $
          newSecretKeyWith $ \secretKeyPtr ->
            Foreign.copyArray
              outsideSecretKeyPtr
              (Foreign.castPtr @CUChar @CChar secretKeyPtr)
              (fromIntegral cryptoSecretboxKeyBytes)

-- | Prepare memory for a 'SecretKey' and use the provided action to fill it.
--
-- Memory is allocated with 'LibSodium.Bindings.SecureMemory.sodiumMalloc' (see the note attached there).
-- Finalizer is run when the key is goes out of scope, but 'freeSecretKey' can be used to release early.
--
-- @since 0.0.1.0
newSecretKeyWith :: (Foreign.Ptr CUChar -> IO ()) -> IO SecretKey
newSecretKeyWith action = do
  ptr <- sodiumMalloc cryptoSecretboxKeyBytes
  when (ptr == Foreign.nullPtr) $ do
    throwErrno "sodium_malloc"

  fPtr <- Foreign.newForeignPtr_ ptr
  Foreign.addForeignPtrFinalizer finalizerSodiumFree fPtr
  action ptr
  pure $ SecretKey fPtr

-- | Trigger memory clean up and release without waiting for GC.
--
-- The 'SecretKey' must not be used again.
--
-- @since 0.0.1.0
freeSecretKey :: SecretKey -> IO ()
freeSecretKey (SecretKey fPtr) = Foreign.finalizeForeignPtr fPtr

-- | Convert a 'SecretKey' to a hexadecimal-encoded 'StrictByteString'.
--
-- ⚠️  Be prudent as to where you store it!
--
-- @since 0.0.1.0
unsafeSecretKeyToHexByteString :: SecretKey -> StrictByteString
unsafeSecretKeyToHexByteString (SecretKey secretKeyForeignPtr) =
  Base16.encodeBase16' $
    BS.fromForeignPtr0
      (Foreign.castForeignPtr @CUChar @Word8 secretKeyForeignPtr)
      (fromIntegral @CSize @Int cryptoSecretboxKeyBytes)

-- | A random number that must only be used once per exchanged message.
-- It does not have to be confidential.
-- It is of size 'cryptoSecretboxNonceBytes'.
--
-- @since 0.0.1.0
newtype Nonce = Nonce (ForeignPtr CUChar)
  deriving
    ( Display
      -- ^ @since 0.0.1.0
      -- > display secretKey == "[REDACTED]"
    )
    via (ShowInstance Nonce)

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
instance Show Nonce where
  show = show . nonceToHexByteString

-- | Generate a new random nonce.
-- Only use it once per exchanged message.
--
-- Do not use this outside of hash creation!
newNonce :: IO Nonce
newNonce = do
  (fPtr :: ForeignPtr CUChar) <- Foreign.mallocForeignPtrBytes (fromIntegral cryptoSecretboxNonceBytes)
  Foreign.withForeignPtr fPtr $ \ptr ->
    randombytesBuf (Foreign.castPtr @CUChar @Word8 ptr) cryptoSecretboxNonceBytes
  pure $ Nonce fPtr

-- | Create a 'Nonce' from a binary 'StrictByteString' that you have obtained on your own,
-- usually from the network or disk.
--
-- @since 0.0.1.0
nonceFromByteString :: StrictByteString -> Nonce
nonceFromByteString bytestring = unsafeDupablePerformIO $
  BS.unsafeUseAsCStringLen bytestring $ \(outsideNoncePtr, _) -> do
    nonceForeignPtr <-
      BS.mallocByteString
        @CChar
        (fromIntegral cryptoSecretboxNonceBytes)
    Foreign.withForeignPtr nonceForeignPtr $ \noncePtr ->
      Foreign.copyArray
        outsideNoncePtr
        noncePtr
        (fromIntegral cryptoSecretboxNonceBytes)
    pure $ Nonce (Foreign.castForeignPtr @CChar @CUChar nonceForeignPtr)

-- | Convert a 'Nonce' to a hexadecimal-encoded 'StrictByteString'.
--
-- @since 0.0.1.0
nonceToHexByteString :: Nonce -> StrictByteString
nonceToHexByteString (Nonce nonceForeignPtr) =
  Base16.encodeBase16' $
    BS.fromForeignPtr0
      (Foreign.castForeignPtr @CUChar @Word8 nonceForeignPtr)
      (fromIntegral @CSize @Int cryptoSecretboxKeyBytes)

-- | A ciphertext consisting of an encrypted message and an authentication tag.
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
      result1 <-
        foreignPtrEq
          hk1
          hk2
          (fromIntegral messageLength1 + cryptoSecretboxMACBytes)
      pure $ (messageLength1 == messageLength2) && result1

-- |
--
-- @since 0.0.1.0
instance Ord Hash where
  compare (Hash messageLength1 hk1) (Hash messageLength2 hk2) =
    unsafeDupablePerformIO $ do
      result1 <- foreignPtrOrd hk1 hk2 (fromIntegral messageLength1 + cryptoSecretboxMACBytes)
      pure $ compare messageLength1 messageLength2 <> result1

-- | ⚠️  Be prudent as to what you do with it!
--
-- @since 0.0.1.0
instance Display Hash where
  displayBuilder = Builder.fromText . hashToHexText

-- | ⚠️  Be prudent as to what you do with it!
--
-- @since 0.0.1.0
instance Show Hash where
  show = BS.unpackChars . hashToHexByteString

-- | Create a 'Hash' from a binary 'StrictByteString' that you have obtained on your own,
-- usually from the network or disk. It must be a valid hash built from the concatenation
-- of the encrypted message and the authentication tag.
--
-- @since 0.0.1.0
hashFromByteString :: StrictByteString -> Maybe Hash
hashFromByteString bytestring =
  if BS.length bytestring < fromIntegral cryptoSecretboxMACBytes
    then Nothing
    else unsafeDupablePerformIO $
      BS.unsafeUseAsCStringLen bytestring $ \(outsideHashPtr, outsideHashLength) -> do
        hashForeignPtr <- BS.mallocByteString @CChar outsideHashLength
        Foreign.withForeignPtr hashForeignPtr $ \hashPtr ->
          Foreign.copyArray outsideHashPtr hashPtr outsideHashLength
        pure $
          Just $
            Hash
              (fromIntegral @Int @CULLong outsideHashLength)
              (Foreign.castForeignPtr @CChar @CUChar hashForeignPtr)

-- | Convert a 'Hash' to a hexadecimal-encoded 'Text'.
--
-- ⚠️  Be prudent as to where you store it!
--
-- @since 0.0.1.0
hashToHexText :: Hash -> Text
hashToHexText = Base16.encodeBase16 . hashToBinary

-- | Convert a 'Hash' to a hexadecimal-encoded 'StrictByteString'.
--
-- ⚠️  Be prudent as to where you store it!
--
-- @since 0.0.1.0
hashToHexByteString :: Hash -> StrictByteString
hashToHexByteString = Base16.encodeBase16' . hashToBinary

-- | Convert a 'Hash' to a binary 'StrictByteString'.
--
-- ⚠️  Be prudent as to where you store it!
--
-- @since 0.0.1.0
hashToBinary :: Hash -> StrictByteString
hashToBinary (Hash messageLength fPtr) =
  BS.fromForeignPtr0
    (Foreign.castForeignPtr fPtr)
    (fromIntegral messageLength + fromIntegral cryptoSecretboxMACBytes)

-- | Create an authenticated hash from a message, a secret key,
-- and a one-time cryptographic nonce that must never be re-used with the same
-- secret key to encrypt another message.
--
-- @since 0.0.1.0
encrypt
  :: StrictByteString
  -- ^ Message to encrypt.
  -> SecretKey
  -- ^ Secret key generated with 'newSecretKey'.
  -> IO (Nonce, Hash)
encrypt message (SecretKey secretKeyForeignPtr) =
  BS.unsafeUseAsCStringLen message $ \(cString, cStringLen) -> do
    (Nonce nonceForeignPtr) <- newNonce
    hashForeignPtr <-
      Foreign.mallocForeignPtrBytes
        (cStringLen + fromIntegral cryptoSecretboxMACBytes)
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
    let hash = Hash (fromIntegral @Int @CULLong cStringLen) hashForeignPtr
    pure (Nonce nonceForeignPtr, hash)

-- | Decrypt a hashed and authenticated message with the shared secret key and the one-time cryptographic nonce.
--
-- @since 0.0.1.0
decrypt
  :: Hash
  -- ^ Encrypted message you want to decrypt.
  -> SecretKey
  -- ^ Secret key used for encrypting the original message.
  -> Nonce
  -- ^ Nonce used for encrypting the original message.
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
            Just
              <$> BS.unsafePackMallocCStringLen
                (Foreign.castPtr @CChar bsPtr, fromIntegral messageLength)
