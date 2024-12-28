{-# LANGUAGE DataKinds #-}
{-# LANGUAGE DerivingVia #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TypeApplications #-}

-- |
--
-- Module: Sel.PublicKey.Seal
-- Description: Anonymous ephemeral authenticated encryption with public and secret keys
-- Copyright: (C) Hécate Moonlight 2022
-- License: BSD-3-Clause
-- Maintainer: The Haskell Cryptography Group
-- Portability: GHC only
module Sel.PublicKey.Seal
  ( -- ** Introduction
    -- $introduction

    -- ** Usage
    -- $usage

    -- ** Keys
    PublicKey (..)
  , SecretKey (..)
  , newKeyPair

    -- ** Operations
  , seal
  , open

    -- ** Errors
  , KeyPairGenerationException
  , EncryptionError
  ) where

import Control.Exception (throw)
import Control.Monad (when)
import Data.ByteString (StrictByteString)
import qualified Data.ByteString.Unsafe as BS
import qualified Foreign
import Foreign.C (CChar, CSize, CUChar, CULLong)
import System.IO.Unsafe (unsafeDupablePerformIO)

import LibSodium.Bindings.SealedBoxes
  ( cryptoBoxSeal
  , cryptoBoxSealOpen
  , cryptoBoxSealbytes
  )
import Sel.PublicKey.Cipher
  ( CipherText (CipherText)
  , EncryptionError (..)
  , KeyPairGenerationException
  , PublicKey (PublicKey)
  , SecretKey (..)
  , newKeyPair
  )

-- $introduction
-- Ephemeral authenticated encryption allows to anonymously send message to
-- a recipient given their public key.
--
-- Only the recipient can decrypt these messages using their own secret key.
-- While the recipient can verify the integrity of the message, they cannot
-- verify the identity of the sender.
--
-- A message is encrypted using an ephemeral key pair, with the secret key being erased
-- right after the encryption process.
--
-- Without knowing the secret key used for a given message, the sender cannot decrypt
-- their own message later. Furthermore, without additional data, a message cannot
-- be correlated with the identity of its sender.

-- $usage
--
-- > import qualified Sel.PublicKey.Seal as Seal
-- > import Sel (secureMain)
-- >
-- > main = secureMain $ do
-- >   -- We get the recipient their pair of keys:
-- > (recipientPublicKey, recipientSecretKey) <- newKeyPair
-- >   encryptedMessage <- Seal.encrypt "hello hello" recipientPublicKey
-- >   let result = Seal.open encryptedMessage recipientPublicKey recipientSecretKey
-- >   print result
-- >   -- "Just \"hello hello\""

-- | Encrypt a message with the recipient's public key. A key pair for the sender
-- is generated, and the public key of that pair is attached to the cipher text.
-- The secret key of the sender's pair is automatically destroyed.
--
-- @since 0.0.1.0
seal
  :: StrictByteString
  -- ^ Message to encrypt
  -> PublicKey
  -- ^ Public key of the recipient
  -> IO CipherText
seal messageByteString (PublicKey publicKeyFptr) = do
  BS.unsafeUseAsCStringLen messageByteString $ \(messagePtr, messageLen) -> do
    cipherTextForeignPtr <-
      Foreign.mallocForeignPtrBytes
        (messageLen + fromIntegral cryptoBoxSealbytes)
    Foreign.withForeignPtr publicKeyFptr $ \publicKeyPtr ->
      Foreign.withForeignPtr cipherTextForeignPtr $ \cipherTextPtr -> do
        result <-
          cryptoBoxSeal
            cipherTextPtr
            (Foreign.castPtr @CChar @CUChar messagePtr)
            (fromIntegral @Int @CULLong messageLen)
            publicKeyPtr
        when (result /= 0) $ throw EncryptionError
        pure $
          CipherText
            (fromIntegral @Int @CULLong messageLen)
            cipherTextForeignPtr

-- | Open a sealed message from an unknown sender.
-- You need your public and secret keys.
--
-- @since 0.0.1.0
open
  :: CipherText
  -- ^ Cipher to decrypt
  -> PublicKey
  -- ^ Public key of the recipient
  -> SecretKey
  -- ^ Secret key of the recipient
  -> Maybe StrictByteString
open
  (CipherText messageLen cipherForeignPtr)
  (PublicKey publicKeyFPtr)
  (SecretKey secretKeyFPtr) = unsafeDupablePerformIO $ do
    messagePtr <- Foreign.mallocBytes (fromIntegral @CULLong @Int messageLen)
    Foreign.withForeignPtr cipherForeignPtr $ \cipherTextPtr ->
      Foreign.withForeignPtr publicKeyFPtr $ \publicKeyPtr ->
        Foreign.withForeignPtr secretKeyFPtr $ \secretKeyPtr -> do
          result <-
            cryptoBoxSealOpen
              messagePtr
              cipherTextPtr
              (messageLen + fromIntegral @CSize @CULLong cryptoBoxSealbytes)
              publicKeyPtr
              secretKeyPtr
          case result of
            (-1) -> pure Nothing
            _ -> do
              bsPtr <- Foreign.mallocBytes (fromIntegral messageLen)
              Foreign.copyBytes bsPtr (Foreign.castPtr messagePtr) (fromIntegral messageLen)
              Just
                <$> BS.unsafePackMallocCStringLen
                  (Foreign.castPtr @CUChar @CChar bsPtr, fromIntegral messageLen)
