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

    -- ** Encryption and Decryption
    encrypt
  , decrypt

    -- ** Secret Key
  , SecretKey
  , newSecretKey
  , secretKeyFromHexByteString
  , unsafeSecretKeyToHexByteString

    -- ** Nonce
  , Nonce
  , nonceFromHexByteString
  , nonceToHexByteString

    -- ** Ciphertext
  , Ciphertext
  , ciphertextFromHexByteString
  , ciphertextToBinary
  , ciphertextToHexByteString
  , ciphertextToHexText
  ) where

import Control.Monad (void, when)
import qualified Data.Base16.Types as Base16
import Data.ByteString (StrictByteString)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Base16 as Base16
import qualified Data.ByteString.Internal as BS
import qualified Data.ByteString.Unsafe as BS
import Data.Text (Text)
import qualified Data.Text as Text
import qualified Data.Text.Builder.Linear as Builder
import Data.Text.Display (Display (displayBuilder), OpaqueInstance (..), ShowInstance (..))
import Data.Word (Word8)
import Foreign (ForeignPtr)
import qualified Foreign
import Foreign.C (CChar, CSize, CUChar, CULLong, throwErrno)
import LibSodium.Bindings.Random (randombytesBuf)
import LibSodium.Bindings.Secretbox
  ( cryptoSecretboxEasy
  , cryptoSecretboxKeyBytes
  , cryptoSecretboxKeygen
  , cryptoSecretboxMACBytes
  , cryptoSecretboxNonceBytes
  , cryptoSecretboxOpenEasy
  )
import LibSodium.Bindings.SecureMemory
import System.IO.Unsafe (unsafeDupablePerformIO)

import Sel.Internal
import Sel.Internal.Sodium (binaryToHex)

-- $introduction
-- "Authenticated Encryption" uses a secret key along with a single-use number
-- called a "nonce" to encrypt a message.
-- The resulting ciphertext is accompanied by an authentication tag.
--
-- Encryption is done with the XSalsa20 stream cipher and authentication is done with the
-- Poly1305 MAC hash.

-- $usage
--
-- > import qualified Sel.SecretKey.Cipher as Cipher
-- > import Sel (secureMain)
-- >
-- > main = secureMain $ do
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
    foreignPtrEqConstantTime hk1 hk2 cryptoSecretboxKeyBytes

-- |
--
-- @since 0.0.1.0
instance Ord SecretKey where
  compare (SecretKey hk1) (SecretKey hk2) =
    foreignPtrOrdConstantTime hk1 hk2 cryptoSecretboxKeyBytes

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
-- The input secret key, once decoded from base16, must be of length
-- 'cryptoSecretboxKeyBytes'.
--
-- @since 0.0.1.0
secretKeyFromHexByteString :: StrictByteString -> Either Text SecretKey
secretKeyFromHexByteString hexNonce = unsafeDupablePerformIO $
  case Base16.decodeBase16Untyped hexNonce of
    Right bytestring ->
      if BS.length bytestring == fromIntegral cryptoSecretboxKeyBytes
        then BS.unsafeUseAsCStringLen bytestring $ \(outsideSecretKeyPtr, _) ->
          fmap Right $
            newSecretKeyWith $ \secretKeyPtr ->
              Foreign.copyArray
                (Foreign.castPtr @CUChar @CChar secretKeyPtr)
                outsideSecretKeyPtr
                (fromIntegral cryptoSecretboxKeyBytes)
        else pure $ Left $ Text.pack "Secret Key is too short"
    Left msg -> pure $ Left msg

-- | Prepare memory for a 'SecretKey' and use the provided action to fill it.
--
-- Memory is allocated with 'LibSodium.Bindings.SecureMemory.sodiumMalloc' (see the note attached there).
-- A finalizer is run when the key is goes out of scope.
--
-- @since 0.0.1.0
newSecretKeyWith :: (Foreign.Ptr CUChar -> IO ()) -> IO SecretKey
newSecretKeyWith action = do
  ptr <- sodiumMalloc cryptoSecretboxKeyBytes
  when (ptr == Foreign.nullPtr) $ do
    throwErrno "sodium_malloc"

  fPtr <- Foreign.newForeignPtr finalizerSodiumFree ptr
  action ptr
  pure $ SecretKey fPtr

-- | Convert a 'SecretKey' to a hexadecimal-encoded 'StrictByteString' in constant time.
--
-- ⚠️  Be prudent as to where you store it!
--
-- @since 0.0.1.0
unsafeSecretKeyToHexByteString :: SecretKey -> StrictByteString
unsafeSecretKeyToHexByteString (SecretKey secretKeyForeignPtr) =
  binaryToHex secretKeyForeignPtr cryptoSecretboxKeyBytes

-- | A random number that must only be used once per exchanged message.
-- It does not have to be confidential.
-- It is of size 'cryptoSecretboxNonceBytes'.
--
-- @since 0.0.1.0
newtype Nonce = Nonce (ForeignPtr CUChar)
  deriving
    ( Display
      -- ^ @since 0.0.1.0
    )
    via (ShowInstance Nonce)

-- |
--
-- @since 0.0.1.0
instance Eq Nonce where
  (Nonce hk1) == (Nonce hk2) =
    foreignPtrEq hk1 hk2 cryptoSecretboxNonceBytes

-- |
--
-- @since 0.0.1.0
instance Ord Nonce where
  compare (Nonce hk1) (Nonce hk2) =
    foreignPtrOrd hk1 hk2 cryptoSecretboxNonceBytes

-- |
--
-- @since 0.0.1.0
instance Show Nonce where
  show = show . nonceToHexByteString

-- | Generate a new random nonce.
-- Only use it once per exchanged message.
--
-- Do not use this outside of ciphertext creation!
newNonce :: IO Nonce
newNonce = do
  (fPtr :: ForeignPtr CUChar) <- Foreign.mallocForeignPtrBytes (fromIntegral cryptoSecretboxNonceBytes)
  Foreign.withForeignPtr fPtr $ \ptr ->
    randombytesBuf (Foreign.castPtr @CUChar @Word8 ptr) cryptoSecretboxNonceBytes
  pure $ Nonce fPtr

-- | Create a 'Nonce' from a binary 'StrictByteString' that you have obtained on your own,
-- usually from the network or disk.
-- Once decoded from hexadecimal, it must be of length 'cryptoSecretboxNonceBytes'.
--
-- @since 0.0.1.0
nonceFromHexByteString :: StrictByteString -> Either Text Nonce
nonceFromHexByteString hexNonce = unsafeDupablePerformIO $
  case Base16.decodeBase16Untyped hexNonce of
    Right bytestring ->
      if BS.length bytestring == fromIntegral @CSize @Int cryptoSecretboxNonceBytes
        then BS.unsafeUseAsCStringLen bytestring $ \(outsideNoncePtr, _) -> do
          nonceForeignPtr <-
            BS.mallocByteString
              @CChar
              (fromIntegral cryptoSecretboxNonceBytes)
          Foreign.withForeignPtr nonceForeignPtr $ \noncePtr ->
            Foreign.copyArray
              noncePtr
              outsideNoncePtr
              (fromIntegral cryptoSecretboxNonceBytes)
          pure $ Right $ Nonce (Foreign.castForeignPtr @CChar @CUChar nonceForeignPtr)
        else pure $ Left $ Text.pack "Nonce is too short"
    Left msg -> pure $ Left msg

-- | Convert a 'Nonce' to a hexadecimal-encoded 'StrictByteString' in constant time.
--
-- @since 0.0.1.0
nonceToHexByteString :: Nonce -> StrictByteString
nonceToHexByteString (Nonce nonceForeignPtr) =
  binaryToHex nonceForeignPtr cryptoSecretboxNonceBytes

-- | A ciphertext consisting of an encrypted message and an authentication tag.
--
-- @since 0.0.1.0
data Ciphertext = Ciphertext
  { messageLength :: CULLong
  , ciphertextForeignPtr :: ForeignPtr CUChar
  }

-- |
--
-- @since 0.0.1.0
instance Eq Ciphertext where
  (Ciphertext messageLength1 hk1) == (Ciphertext messageLength2 hk2) =
    let
      messageLength = messageLength1 == messageLength2
      content =
        foreignPtrEqConstantTime
          hk1
          hk2
          (fromIntegral messageLength1 + cryptoSecretboxMACBytes)
     in
      messageLength && content

-- |
--
-- @since 0.0.1.0
instance Ord Ciphertext where
  compare (Ciphertext messageLength1 hk1) (Ciphertext messageLength2 hk2) =
    let
      messageLength = compare messageLength1 messageLength2
      content =
        foreignPtrOrdConstantTime
          hk1
          hk2
          (fromIntegral messageLength1 + cryptoSecretboxMACBytes)
     in
      messageLength <> content

-- | ⚠️  Be prudent as to what you do with it!
--
-- @since 0.0.1.0
instance Display Ciphertext where
  displayBuilder = Builder.fromText . ciphertextToHexText

-- | ⚠️  Be prudent as to what you do with it!
--
-- @since 0.0.1.0
instance Show Ciphertext where
  show = BS.unpackChars . ciphertextToHexByteString

-- | Create a 'Ciphertext' from a hexadecimal-encoded 'StrictByteString' that
-- you have obtained on your own, usually from the network or disk. It must be
-- a valid ciphertext built from the concatenation of the encrypted message and
-- the authentication tag.
--
-- The input ciphertext must at least of length 'cryptoSecretboxMACBytes'.
--
-- @since 0.0.1.0
ciphertextFromHexByteString :: StrictByteString -> Either Text Ciphertext
ciphertextFromHexByteString hexCiphertext = unsafeDupablePerformIO $
  case Base16.decodeBase16Untyped hexCiphertext of
    Right bytestring ->
      if BS.length bytestring >= fromIntegral cryptoSecretboxMACBytes
        then BS.unsafeUseAsCStringLen bytestring $ \(outsideCiphertextPtr, outsideCiphertextLength) -> do
          ciphertextForeignPtr <- BS.mallocByteString @CChar outsideCiphertextLength -- The foreign pointer that will receive the ciphertext data.
          Foreign.withForeignPtr ciphertextForeignPtr $ \ciphertextPtr ->
            -- We copy bytes from 'outsideCiphertextPtr' to 'ciphertextPtr'.
            Foreign.copyArray ciphertextPtr outsideCiphertextPtr outsideCiphertextLength
          pure $
            Right $
              Ciphertext
                (fromIntegral @Int @CULLong outsideCiphertextLength - fromIntegral @CSize @CULLong cryptoSecretboxMACBytes)
                (Foreign.castForeignPtr @CChar @CUChar ciphertextForeignPtr)
        else pure $ Left $ Text.pack "Ciphertext is too short"
    Left msg -> pure $ Left msg

-- | Convert a 'Ciphertext' to a hexadecimal-encoded 'Text'.
--
-- ⚠️  Be prudent as to where you store it!
--
-- @since 0.0.1.0
ciphertextToHexText :: Ciphertext -> Text
ciphertextToHexText = Base16.extractBase16 . Base16.encodeBase16 . ciphertextToBinary

-- | Convert a 'Ciphertext' to a hexadecimal-encoded 'StrictByteString' in constant time.
--
-- ⚠️  Be prudent as to where you store it!
--
-- @since 0.0.1.0
ciphertextToHexByteString :: Ciphertext -> StrictByteString
ciphertextToHexByteString (Ciphertext messageLength fPtr) =
  binaryToHex fPtr (cryptoSecretboxMACBytes + fromIntegral messageLength)

-- | Convert a 'Ciphertext' to a binary 'StrictByteString'.
--
-- ⚠️  Be prudent as to where you store it!
--
-- @since 0.0.1.0
ciphertextToBinary :: Ciphertext -> StrictByteString
ciphertextToBinary (Ciphertext messageLength fPtr) =
  BS.fromForeignPtr0
    (Foreign.castForeignPtr fPtr)
    (fromIntegral messageLength + fromIntegral cryptoSecretboxMACBytes)

-- | Create an authenticated ciphertext from a message, a secret key,
-- and a one-time cryptographic nonce that must never be re-used with the same
-- secret key to encrypt another message.
--
-- @since 0.0.1.0
encrypt
  :: StrictByteString
  -- ^ Message to encrypt.
  -> SecretKey
  -- ^ Secret key generated with 'newSecretKey'.
  -> IO (Nonce, Ciphertext)
encrypt message (SecretKey secretKeyForeignPtr) =
  BS.unsafeUseAsCStringLen message $ \(cString, cStringLen) -> do
    (Nonce nonceForeignPtr) <- newNonce
    ciphertextForeignPtr <-
      Foreign.mallocForeignPtrBytes
        (cStringLen + fromIntegral cryptoSecretboxMACBytes)
    Foreign.withForeignPtr ciphertextForeignPtr $ \ciphertextPtr ->
      Foreign.withForeignPtr secretKeyForeignPtr $ \secretKeyPtr ->
        Foreign.withForeignPtr nonceForeignPtr $ \noncePtr -> do
          void $
            cryptoSecretboxEasy
              ciphertextPtr
              (Foreign.castPtr @CChar @CUChar cString)
              (fromIntegral @Int @CULLong cStringLen)
              noncePtr
              secretKeyPtr
    let ciphertext = Ciphertext (fromIntegral @Int @CULLong cStringLen) ciphertextForeignPtr
    pure (Nonce nonceForeignPtr, ciphertext)

-- | Decrypt an encrypted and authenticated message with the shared secret key and the one-time cryptographic nonce.
--
-- @since 0.0.1.0
decrypt
  :: Ciphertext
  -- ^ Encrypted message you want to decrypt.
  -> SecretKey
  -- ^ Secret key used for encrypting the original message.
  -> Nonce
  -- ^ Nonce used for encrypting the original message.
  -> Maybe StrictByteString
decrypt Ciphertext{messageLength, ciphertextForeignPtr} (SecretKey secretKeyForeignPtr) (Nonce nonceForeignPtr) = unsafeDupablePerformIO $ do
  messagePtr <- Foreign.mallocBytes (fromIntegral @CULLong @Int messageLength)
  Foreign.withForeignPtr ciphertextForeignPtr $ \ciphertextPtr ->
    Foreign.withForeignPtr secretKeyForeignPtr $ \secretKeyPtr ->
      Foreign.withForeignPtr nonceForeignPtr $ \noncePtr -> do
        result <-
          cryptoSecretboxOpenEasy
            messagePtr
            ciphertextPtr
            (messageLength + fromIntegral cryptoSecretboxMACBytes)
            noncePtr
            secretKeyPtr
        case result of
          (-1) -> pure Nothing
          _ -> do
            bsPtr <- Foreign.mallocBytes (fromIntegral messageLength)
            Foreign.copyBytes bsPtr messagePtr (fromIntegral messageLength)
            Just
              <$> BS.unsafePackMallocCStringLen
                (Foreign.castPtr @CUChar @CChar bsPtr, fromIntegral messageLength)
