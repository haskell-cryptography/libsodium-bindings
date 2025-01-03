{-# LANGUAGE DerivingStrategies #-}
{-# LANGUAGE NamedFieldPuns #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TypeApplications #-}

-- |
--
-- Module: Sel.PublicKey.Signature
-- Description: Public-key signatures with the Ed25519 algorithm
-- Copyright: (C) Hécate Moonlight 2022
-- License: BSD-3-Clause
-- Maintainer: The Haskell Cryptography Group
-- Portability: GHC only
module Sel.PublicKey.Signature
  ( -- ** Introduction
    -- $introduction
    PublicKey
  , SecretKey
  , SignedMessage

    -- ** Key Pair generation
  , generateKeyPair

    -- ** Message Signing
  , signMessage
  , openMessage

    -- ** Constructing and Deconstructing
  , getSignature
  , unsafeGetMessage
  , mkSignature
  )
where

import Control.Monad (void)
import Data.ByteString (StrictByteString)
import Data.ByteString.Unsafe (unsafePackMallocCStringLen)
import qualified Data.ByteString.Unsafe as ByteString
import Foreign
  ( ForeignPtr
  , Ptr
  , castPtr
  , mallocBytes
  , mallocForeignPtrBytes
  , withForeignPtr
  )
import Foreign.C (CChar, CSize, CUChar, CULLong)
import qualified Foreign.Marshal.Array as Foreign
import qualified Foreign.Ptr as Foreign
import GHC.IO.Handle.Text (memcpy)
import System.IO.Unsafe (unsafeDupablePerformIO)

import LibSodium.Bindings.CryptoSign
  ( cryptoSignBytes
  , cryptoSignDetached
  , cryptoSignKeyPair
  , cryptoSignPublicKeyBytes
  , cryptoSignSecretKeyBytes
  , cryptoSignVerifyDetached
  )
import Sel.Internal

-- $introduction
--
-- Public-key Signatures work with a 'SecretKey' and 'PublicKey'
--
-- * The 'SecretKey' is used to append a signature to any number of messages. It must stay private;
-- * The 'PublicKey' is used by third-parties to to verify that the signature appended to a message was
-- issued by the creator of the public key. It must be distributed to third-parties.
--
-- Verifiers need to already know and ultimately trust a public key before messages signed
-- using it can be verified.

-- |
--
-- @since 0.0.1.0
newtype PublicKey = PublicKey (ForeignPtr CUChar)

-- |
--
-- @since 0.0.1.0
instance Eq PublicKey where
  (PublicKey pk1) == (PublicKey pk2) =
    foreignPtrEq pk1 pk2 cryptoSignPublicKeyBytes

-- |
--
-- @since 0.0.1.0
instance Ord PublicKey where
  compare (PublicKey pk1) (PublicKey pk2) =
    foreignPtrOrd pk1 pk2 cryptoSignPublicKeyBytes

-- |
--
-- @since 0.0.1.0
newtype SecretKey = SecretKey (ForeignPtr CUChar)

-- |
--
-- @since 0.0.1.0
instance Eq SecretKey where
  (SecretKey sk1) == (SecretKey sk2) =
    foreignPtrEqConstantTime sk1 sk2 cryptoSignSecretKeyBytes

-- |
--
-- @since 0.0.1.0
instance Ord SecretKey where
  compare (SecretKey sk1) (SecretKey sk2) =
    foreignPtrOrd sk1 sk2 cryptoSignSecretKeyBytes

-- |
--
-- @since 0.0.1.0
data SignedMessage = SignedMessage
  { messageLength :: CSize
  , messageForeignPtr :: ForeignPtr CUChar
  , signatureForeignPtr :: ForeignPtr CUChar
  }

-- |
--
-- @since 0.0.1.0
instance Eq SignedMessage where
  (SignedMessage len1 msg1 sig1) == (SignedMessage len2 msg2 sig2) =
    let
      messageLength = len1 == len2
      msg1Eq = foreignPtrEq msg1 msg2 len1
      msg2Eq = foreignPtrEq sig1 sig2 cryptoSignBytes
     in
      messageLength && msg1Eq && msg2Eq

-- |
--
-- @since 0.0.1.0
instance Ord SignedMessage where
  compare (SignedMessage len1 msg1 sig1) (SignedMessage len2 msg2 sig2) =
    let
      messageLength = compare len1 len2
      msg1Ord = foreignPtrOrd msg1 msg2 len1
      msg2Ord = foreignPtrOrd sig1 sig2 cryptoSignBytes
     in
      messageLength <> msg1Ord <> msg2Ord

-- | Generate a pair of public and secret key.
--
-- The length parameters used are 'cryptoSignPublicKeyBytes'
-- and 'cryptoSignSecretKeyBytes'.
--
-- @since 0.0.1.0
generateKeyPair :: IO (PublicKey, SecretKey)
generateKeyPair = do
  publicKeyForeignPtr <- mallocForeignPtrBytes (fromIntegral @CSize @Int cryptoSignPublicKeyBytes)
  secretKeyForeignPtr <- mallocForeignPtrBytes (fromIntegral @CSize @Int cryptoSignSecretKeyBytes)
  withForeignPtr publicKeyForeignPtr $ \pkPtr ->
    withForeignPtr secretKeyForeignPtr $ \skPtr ->
      void $
        cryptoSignKeyPair
          pkPtr
          skPtr
  pure (PublicKey publicKeyForeignPtr, SecretKey secretKeyForeignPtr)

-- | Sign a message.
--
-- @since 0.0.1.0
signMessage :: StrictByteString -> SecretKey -> IO SignedMessage
signMessage message (SecretKey skFPtr) =
  ByteString.unsafeUseAsCStringLen message $ \(cString, messageLength) -> do
    let sigLength = fromIntegral @CSize @Int cryptoSignBytes
    (messageForeignPtr :: ForeignPtr CUChar) <- Foreign.mallocForeignPtrBytes messageLength
    signatureForeignPtr <- Foreign.mallocForeignPtrBytes sigLength
    withForeignPtr messageForeignPtr $ \messagePtr ->
      withForeignPtr signatureForeignPtr $ \signaturePtr ->
        withForeignPtr skFPtr $ \skPtr -> do
          Foreign.copyArray messagePtr (Foreign.castPtr @CChar @CUChar cString) messageLength
          void $
            cryptoSignDetached
              signaturePtr
              Foreign.nullPtr -- Always of size 'cryptoSignBytes'
              (castPtr @CChar @CUChar cString)
              (fromIntegral @Int @CULLong messageLength)
              skPtr
    pure $ SignedMessage (fromIntegral @Int @CSize messageLength) messageForeignPtr signatureForeignPtr

-- | Open a signed message with the signatory's public key.
-- The function returns 'Nothing' if there is a key mismatch.
--
-- @since 0.0.1.0
openMessage :: SignedMessage -> PublicKey -> Maybe StrictByteString
openMessage SignedMessage{messageLength, messageForeignPtr, signatureForeignPtr} (PublicKey pkForeignPtr) = unsafeDupablePerformIO $
  withForeignPtr pkForeignPtr $ \publicKeyPtr ->
    withForeignPtr signatureForeignPtr $ \signaturePtr -> do
      withForeignPtr messageForeignPtr $ \messagePtr -> do
        result <-
          cryptoSignVerifyDetached
            signaturePtr
            messagePtr
            (fromIntegral @CSize @CULLong messageLength)
            publicKeyPtr
        case result of
          (-1) -> pure Nothing
          _ -> do
            bsPtr <- mallocBytes (fromIntegral messageLength)
            memcpy bsPtr (castPtr messagePtr) messageLength
            Just <$> unsafePackMallocCStringLen (castPtr bsPtr :: Ptr CChar, fromIntegral messageLength)

-- | Get the signature part of a 'SignedMessage'.
--
-- @since 0.0.1.0
getSignature :: SignedMessage -> StrictByteString
getSignature SignedMessage{signatureForeignPtr} = unsafeDupablePerformIO $
  withForeignPtr signatureForeignPtr $ \signaturePtr -> do
    bsPtr <- Foreign.mallocBytes (fromIntegral cryptoSignBytes)
    memcpy bsPtr signaturePtr cryptoSignBytes
    unsafePackMallocCStringLen (Foreign.castPtr bsPtr :: Ptr CChar, fromIntegral cryptoSignBytes)

-- | Get the message part of a 'SignedMessage' __without verifying the signature__.
--
-- @since 0.0.1.0
unsafeGetMessage :: SignedMessage -> StrictByteString
unsafeGetMessage SignedMessage{messageLength, messageForeignPtr} = unsafeDupablePerformIO $
  withForeignPtr messageForeignPtr $ \messagePtr -> do
    bsPtr <- Foreign.mallocBytes (fromIntegral messageLength)
    memcpy bsPtr messagePtr messageLength
    unsafePackMallocCStringLen (Foreign.castPtr bsPtr :: Ptr CChar, fromIntegral messageLength)

-- | Combine a message and a signature into a 'SignedMessage'.
--
-- @since 0.0.1.0
mkSignature :: StrictByteString -> StrictByteString -> SignedMessage
mkSignature message signature = unsafeDupablePerformIO $
  ByteString.unsafeUseAsCStringLen message $ \(messageStringPtr, messageLength) ->
    ByteString.unsafeUseAsCStringLen signature $ \(signatureStringPtr, _) -> do
      (messageForeignPtr :: ForeignPtr CUChar) <- Foreign.mallocForeignPtrBytes messageLength
      signatureForeignPtr <- Foreign.mallocForeignPtrBytes (fromIntegral cryptoSignBytes)
      withForeignPtr messageForeignPtr $ \messagePtr ->
        withForeignPtr signatureForeignPtr $ \signaturePtr -> do
          Foreign.copyArray messagePtr (Foreign.castPtr messageStringPtr) messageLength
          Foreign.copyArray signaturePtr (Foreign.castPtr signatureStringPtr) (fromIntegral cryptoSignBytes)
      pure $ SignedMessage (fromIntegral @Int @CSize messageLength) messageForeignPtr signatureForeignPtr
