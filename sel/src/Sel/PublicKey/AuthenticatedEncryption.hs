{-# LANGUAGE DataKinds #-}
{-# LANGUAGE DeriveAnyClass #-}
{-# LANGUAGE DerivingVia #-}
{-# LANGUAGE NamedFieldPuns #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TypeApplications #-}

-- |
--
-- Module: Sel.PublicKey.AuthenticatedEncryption
-- Description: Public key authenticated encryption with X25519, XSalsa20 and Poly1305
-- Copyright: (C) Hécate Moonlight 2022
-- License: BSD-3-Clause
-- Maintainer: The Haskell Cryptography Group
-- Portability: GHC only
module Sel.PublicKey.AuthenticatedEncryption
  ( -- ** Introduction
    -- $introduction

    -- ** Usage
    -- $usage

    -- ** Key pair generation
    SecretKey
  , PublicKey
  , newKeyPair
  , secretKeyPairFromByteStrings
  , freeSecretKey
  , unsafeSecretKeyToHexByteString
  , unsafePublicKeyToHexByteString

    -- ** Nonce
  , Nonce
  , nonceFromByteString
  , nonceToHexByteString

    -- ** Hash
  , Hash
  , hashFromByteString
  , hashToHexText
  , hashToHexByteString
  , hashToBinary

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
import Foreign (ForeignPtr, Ptr)
import qualified Foreign
import Foreign.C (CChar, CSize, CUChar, CULLong)
import qualified Foreign.C as Foreign
import GHC.IO.Handle.Text (memcpy)
import System.IO.Unsafe (unsafeDupablePerformIO)

import Control.Exception
import LibSodium.Bindings.CryptoBox
import LibSodium.Bindings.Random (randombytesBuf)
import LibSodium.Bindings.SecureMemory
import Sel.Internal

-- $introduction
-- Public-key authenticated encryption allows a sender to encrypt a confidential message
-- specifically for the recipient, using the recipient's public key.

-- $usage
--
-- > import qualified Sel.PublicKey.AuthenticatedEncryption as AuthenticatedEncryption
-- >
-- > main = do
-- >   -- We get the sender their pair of keys:
-- >   (senderSecretKey, senderPublicKey) <- newKeyPair
-- >   -- We get the nonce from the other party with the message, or with 'encrypt' and our own message.
-- >   -- Do not reuse a nonce with the same secret key!
-- >   (nonce, encryptedMessage) <- AuthenticatedEncryption.encrypt "hello hello" secretKey
-- >   let result = AuthenticatedEncryption.decrypt encryptedMessage secretKey nonce
-- >   print result
-- >   -- "Just \"hello hello\""

-- | A secret key of size 'cryptoBoxSecretKeyBytes'.
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
      foreignPtrEq hk1 hk2 cryptoBoxSecretKeyBytes

-- |
--
-- @since 0.0.1.0
instance Ord SecretKey where
  compare (SecretKey hk1) (SecretKey hk2) =
    unsafeDupablePerformIO $
      foreignPtrOrd hk1 hk2 cryptoBoxSecretKeyBytes

-- | > show secretKey == "[REDACTED]"
--
-- @since 0.0.1.0
instance Show SecretKey where
  show _ = "[REDACTED]"

-- | A public key of size 'cryptoBoxPublicKeyBytes'.
--
-- @since 0.0.1.0
newtype PublicKey = PublicKey (ForeignPtr CUChar)
  deriving
    ( Display
      -- ^ @since 0.0.1.0
      -- > display secretKey == "[REDACTED]"
    )
    via (OpaqueInstance "[REDACTED]" PublicKey)

-- |
--
-- @since 0.0.1.0
instance Eq PublicKey where
  (PublicKey hk1) == (PublicKey hk2) =
    unsafeDupablePerformIO $
      foreignPtrEq hk1 hk2 cryptoBoxPublicKeyBytes

-- |
--
-- @since 0.0.1.0
instance Ord PublicKey where
  compare (PublicKey hk1) (PublicKey hk2) =
    unsafeDupablePerformIO $
      foreignPtrOrd hk1 hk2 cryptoBoxPublicKeyBytes

-- | > show secretKey == "[REDACTED]"
--
-- @since 0.0.1.0
instance Show PublicKey where
  show _ = "[REDACTED]"

data KeyPairGenerationException = KeyPairGenerationException
  deriving stock (Eq, Ord, Show)
  deriving anyclass (Exception)

-- | Generate a new random secret key.
--
-- @since 0.0.1.0
newKeyPair :: IO (SecretKey, PublicKey)
newKeyPair = newKeyPairWith $ \secretKeyPtr publicKeyPtr -> do
  result <- cryptoBoxKeyPair secretKeyPtr publicKeyPtr
  when (result /= 0) $ throw KeyPairGenerationException

-- | Create a 'SecretKey' from a binary 'StrictByteString' that you have obtained on your own,
-- usually from the network or disk.
--
-- @since 0.0.1.0
secretKeyPairFromByteStrings
  :: StrictByteString
  -- ^ Secret key
  -> StrictByteString
  -- @ Public keyu
  -> Maybe (SecretKey, PublicKey)
secretKeyPairFromByteStrings secretByteString publicByteString =
  if BS.length secretByteString < fromIntegral cryptoBoxSecretKeyBytes
    || BS.length publicByteString < fromIntegral cryptoBoxPublicKeyBytes
    then Nothing
    else unsafeDupablePerformIO $
      BS.unsafeUseAsCString secretByteString $ \outsideSecretKeyPtr ->
        BS.unsafeUseAsCString publicByteString $ \outsidePublicKeyPtr ->
          fmap Just $
            newKeyPairWith $ \secretKeyPtr publicKeyPtr -> do
              Foreign.copyArray
                outsideSecretKeyPtr
                (Foreign.castPtr @CUChar @CChar secretKeyPtr)
                (fromIntegral cryptoBoxSecretKeyBytes)

              Foreign.copyArray
                outsidePublicKeyPtr
                (Foreign.castPtr @CUChar @CChar publicKeyPtr)
                (fromIntegral cryptoBoxPublicKeyBytes)

-- | Prepare memory for a 'SecretKey' and 'PublicKey' pair,
-- and use the provided action to fill it.
--
-- Memory is allocated with 'LibSodium.Bindings.SecureMemory.sodiumMalloc' (see the note attached there).
-- Finalizer is run when the key is goes out of scope, but 'freeSecretKey' can be used to release early.
--
-- @since 0.0.1.0
newKeyPairWith
  :: ( Ptr CUChar
       -- \^ Secret Key pointer
       -> Ptr CUChar
       -- \^ Public Key pointer
       -> IO ()
     )
  -> IO (SecretKey, PublicKey)
newKeyPairWith action = do
  secretKeyPtr <- sodiumMalloc cryptoBoxSecretKeyBytes
  publicKeyPtr <- sodiumMalloc cryptoBoxPublicKeyBytes
  when (secretKeyPtr == Foreign.nullPtr || publicKeyPtr == Foreign.nullPtr) $ do
    Foreign.throwErrno "sodium_malloc"

  secretKeyForeignPtr <- Foreign.newForeignPtr_ secretKeyPtr
  Foreign.addForeignPtrFinalizer finalizerSodiumFree secretKeyForeignPtr
  publicKeyForeignPtr <- Foreign.newForeignPtr_ publicKeyPtr
  Foreign.addForeignPtrFinalizer finalizerSodiumFree publicKeyForeignPtr
  action secretKeyPtr publicKeyPtr
  pure (SecretKey secretKeyForeignPtr, PublicKey publicKeyForeignPtr)

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
      (fromIntegral @CSize @Int cryptoBoxSecretKeyBytes)

--

-- | Convert a 'SecretKey' to a hexadecimal-encoded 'StrictByteString'.
--
-- ⚠️  Be prudent as to where you store it!
--
-- @since 0.0.1.0
unsafePublicKeyToHexByteString :: PublicKey -> StrictByteString
unsafePublicKeyToHexByteString (PublicKey publicKeyForeignPtr) =
  Base16.encodeBase16' $
    BS.fromForeignPtr0
      (Foreign.castForeignPtr @CUChar @Word8 publicKeyForeignPtr)
      (fromIntegral @CSize @Int cryptoBoxPublicKeyBytes)

-- | A random number that must only be used once per exchanged message.
-- It does not have to be confidential.
-- It is of size 'cryptoBoxNonceBytes'.
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
      foreignPtrEq hk1 hk2 cryptoBoxNonceBytes

-- |
--
-- @since 0.0.1.0
instance Ord Nonce where
  compare (Nonce hk1) (Nonce hk2) =
    unsafeDupablePerformIO $
      foreignPtrOrd hk1 hk2 cryptoBoxNonceBytes

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
  (fPtr :: ForeignPtr CUChar) <- Foreign.mallocForeignPtrBytes (fromIntegral cryptoBoxNonceBytes)
  Foreign.withForeignPtr fPtr $ \ptr ->
    randombytesBuf (Foreign.castPtr @CUChar @Word8 ptr) cryptoBoxNonceBytes
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
        (fromIntegral cryptoBoxNonceBytes)
    Foreign.withForeignPtr nonceForeignPtr $ \noncePtr ->
      Foreign.copyArray
        outsideNoncePtr
        noncePtr
        (fromIntegral cryptoBoxNonceBytes)
    pure $ Nonce (Foreign.castForeignPtr @CChar @CUChar nonceForeignPtr)

-- | Convert a 'Nonce' to a hexadecimal-encoded 'StrictByteString'.
--
-- @since 0.0.1.0
nonceToHexByteString :: Nonce -> StrictByteString
nonceToHexByteString (Nonce nonceForeignPtr) =
  Base16.encodeBase16' $
    BS.fromForeignPtr0
      (Foreign.castForeignPtr @CUChar @Word8 nonceForeignPtr)
      (fromIntegral @CSize @Int cryptoBoxNonceBytes)

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
      let result1 = messageLength1 == messageLength2
      result2 <-
        foreignPtrEq
          hk1
          hk2
          (fromIntegral messageLength1)
      pure $ result1 && result2

-- |
--
-- @since 0.0.1.0
instance Ord Hash where
  compare (Hash messageLength1 hk1) (Hash messageLength2 hk2) =
    unsafeDupablePerformIO $ do
      let result1 = compare messageLength1 messageLength2
      result2 <- foreignPtrOrd hk1 hk2 (fromIntegral messageLength1 + cryptoBoxMACBytes)
      pure $ result1 <> result2

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
  if BS.length bytestring < fromIntegral cryptoBoxMACBytes
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
    (fromIntegral messageLength + fromIntegral cryptoBoxMACBytes)

-- | Create an authenticated hash from a message, a secret key,
-- and a one-time cryptographic nonce that must never be re-used with the same
-- secret key to encrypt another message.
--
-- @since 0.0.1.0
encrypt
  :: StrictByteString
  -- ^ Message to encrypt.
  -> SecretKey
  -- ^ Secret key of the sender
  -> PublicKey
  -- ^ Public key of the recipient
  -> IO (Nonce, Hash)
encrypt message (SecretKey secretKeyForeignPtr) (PublicKey publicKeyForeignPtr) =
  BS.unsafeUseAsCStringLen message $ \(cString, cStringLen) -> do
    (Nonce nonceForeignPtr) <- newNonce
    hashForeignPtr <- Foreign.mallocForeignPtrBytes (cStringLen + fromIntegral cryptoBoxMACBytes)
    Foreign.withForeignPtr hashForeignPtr $ \hashPtr ->
      Foreign.withForeignPtr secretKeyForeignPtr $ \secretKeyPtr ->
        Foreign.withForeignPtr publicKeyForeignPtr $ \publicKeyPtr ->
          Foreign.withForeignPtr nonceForeignPtr $ \noncePtr -> do
            void $
              cryptoBoxEasy
                hashPtr
                (Foreign.castPtr @CChar @CUChar cString)
                (fromIntegral @Int @CULLong cStringLen)
                noncePtr
                publicKeyPtr
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
  -- ^ Secret key of the recipient.
  -> PublicKey
  -- ^ Public key of the sender.
  -> Nonce
  -- ^ Nonce used for encrypting the original message.
  -> Maybe StrictByteString
decrypt
  Hash{messageLength, hashForeignPtr}
  (SecretKey secretKeyForeignPtr)
  (PublicKey publicKeyForeignPtr)
  (Nonce nonceForeignPtr) = unsafeDupablePerformIO $ do
    messagePtr <- Foreign.mallocBytes (fromIntegral @CULLong @Int messageLength)
    Foreign.withForeignPtr hashForeignPtr $ \hashPtr ->
      Foreign.withForeignPtr secretKeyForeignPtr $ \secretKeyPtr ->
        Foreign.withForeignPtr publicKeyForeignPtr $ \publicKeyPtr ->
          Foreign.withForeignPtr nonceForeignPtr $ \noncePtr -> do
            result <-
              cryptoBoxOpenEasy
                messagePtr
                hashPtr
                (messageLength + fromIntegral cryptoBoxMACBytes)
                noncePtr
                publicKeyPtr
                secretKeyPtr
            case result of
              (-1) -> pure Nothing
              _ -> do
                bsPtr <- Foreign.mallocBytes (fromIntegral messageLength)
                memcpy bsPtr (Foreign.castPtr messagePtr) (fromIntegral messageLength)
                Just
                  <$> BS.unsafePackMallocCStringLen
                    (Foreign.castPtr @CChar bsPtr, fromIntegral messageLength)
