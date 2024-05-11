{-# LANGUAGE DataKinds #-}
{-# LANGUAGE DeriveAnyClass #-}
{-# LANGUAGE DerivingVia #-}
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

    -- ** Public and Secret keys
    PublicKey
  , publicKeyToHexByteString
  , publicKeyFromHexByteString
  , publicKeyFromSecretKey
  , SecretKey
  , unsafeSecretKeyToHexByteString
  , secretKeyFromHexByteString
  , SignedMessage

    -- ** Key Pair generation
  , generateKeyPair

    -- ** Message Signing
  , signMessage
  , openMessage

    -- ** Constructing and Deconstructing signatures
  , getSignature
  , unsafeGetMessage
  , mkSignature

    -- ** Exceptions
  , PublicKeyExtractionException (..)
  )
where

import Control.Monad (void, when)
import qualified Data.Base16.Types as Base16
import Data.ByteString (StrictByteString)
import qualified Data.ByteString as ByteString
import qualified Data.ByteString.Base16 as Base16
import qualified Data.ByteString.Internal as ByteString
import qualified Data.ByteString.Unsafe as ByteString
import Data.Text.Display (Display, OpaqueInstance (..), ShowInstance (..))
import Foreign
  ( ForeignPtr
  , Ptr
  , Word8
  , castPtr
  , mallocBytes
  , mallocForeignPtrBytes
  , withForeignPtr
  )
import qualified Foreign
import Foreign.C (CChar, CSize, CUChar, CULLong, throwErrno)
import GHC.IO.Handle.Text (memcpy)
import System.IO.Unsafe (unsafeDupablePerformIO)

import Control.Exception (Exception, throw)
import Data.Text (Text)
import qualified Data.Text as Text
import LibSodium.Bindings.CryptoSign
  ( cryptoSignBytes
  , cryptoSignDetached
  , cryptoSignED25519SkToPk
  , cryptoSignKeyPair
  , cryptoSignPublicKeyBytes
  , cryptoSignSecretKeyBytes
  , cryptoSignVerifyDetached
  )
import LibSodium.Bindings.SecureMemory (finalizerSodiumFree, sodiumMalloc)
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

-- | A public key of size 'cryptoSignPublicKeyBytes'.
--
-- @since 0.0.1.0
newtype PublicKey = PublicKey (ForeignPtr CUChar)
  deriving
    ( Display
      -- ^ @since 0.0.2.0
    )
    via (ShowInstance PublicKey)

-- |
--
-- @since 0.0.1.0
instance Eq PublicKey where
  (PublicKey pk1) == (PublicKey pk2) =
    unsafeDupablePerformIO $
      foreignPtrEq pk1 pk2 cryptoSignPublicKeyBytes

-- |
--
-- @since 0.0.1.0
instance Ord PublicKey where
  compare (PublicKey pk1) (PublicKey pk2) =
    unsafeDupablePerformIO $
      foreignPtrOrd pk1 pk2 cryptoSignPublicKeyBytes

-- |
--
-- @since 0.0.2.0
instance Show PublicKey where
  show = ByteString.unpackChars . publicKeyToHexByteString

-- | Convert a 'PublicKey' to a hexadecimal-encoded 'StrictByteString'.
--
-- @since 0.0.2.0
publicKeyToHexByteString :: PublicKey -> StrictByteString
publicKeyToHexByteString (PublicKey publicKeyForeignPtr) =
  Base16.extractBase16 . Base16.encodeBase16' $
    ByteString.fromForeignPtr0
      (Foreign.castForeignPtr @CUChar @Word8 publicKeyForeignPtr)
      (fromIntegral @CSize @Int cryptoSignPublicKeyBytes)

-- | Create a 'PublicKey' from a binary 'StrictByteString' that you have obtained on your own,
-- usually from the network or disk.
--
-- The input public key, once decoded from base16, must be of length
-- 'cryptoSignKeyBytes'.
--
-- @since 0.0.1.0
publicKeyFromHexByteString :: StrictByteString -> Either Text PublicKey
publicKeyFromHexByteString hexNonce = unsafeDupablePerformIO $
  case Base16.decodeBase16Untyped hexNonce of
    Right bytestring ->
      if ByteString.length bytestring == fromIntegral cryptoSignPublicKeyBytes
        then ByteString.unsafeUseAsCStringLen bytestring $ \(outsidePublicKeyPtr, _) ->
          fmap Right $
            newPublicKeyWith $ \publicKeyPtr ->
              Foreign.copyArray
                (Foreign.castPtr @CUChar @CChar publicKeyPtr)
                outsidePublicKeyPtr
                (fromIntegral cryptoSignPublicKeyBytes)
        else pure $ Left $ Text.pack "Public Key is too short"
    Left msg -> pure $ Left msg

-- | Produce the 'PublicKey' from a 'SecretKey'.
--
-- This function may throw a 'PublicKeyExtractionException' if the operation fails.
--
-- @since 0.0.2.0
publicKeyFromSecretKey :: SecretKey -> PublicKey
publicKeyFromSecretKey (SecretKey secretKeyForeignPtr) = unsafeDupablePerformIO $ do
  publicKeyForeignPtr <- mallocForeignPtrBytes (fromIntegral @CSize @Int cryptoSignPublicKeyBytes)
  withForeignPtr publicKeyForeignPtr $ \pkPtr ->
    withForeignPtr secretKeyForeignPtr $ \skPtr -> do
      result <-
        cryptoSignED25519SkToPk
          pkPtr
          skPtr
      when (result /= 0) $ throw PublicKeyExtractionException
  pure (PublicKey publicKeyForeignPtr)

-- | Prepare memory for a 'SecretKey' and use the provided action to fill it.
--
-- Memory is allocated with 'LibSodium.Bindings.SecureMemory.sodiumMalloc' (see the note attached there).
-- A finalizer is run when the key is goes out of scope.
--
-- @since 0.0.1.0
newPublicKeyWith :: (Foreign.Ptr CUChar -> IO ()) -> IO PublicKey
newPublicKeyWith action = do
  ptr <- sodiumMalloc cryptoSignPublicKeyBytes
  when (ptr == Foreign.nullPtr) $ do
    throwErrno "sodium_malloc"
  fPtr <- Foreign.newForeignPtr finalizerSodiumFree ptr
  action ptr
  pure $ PublicKey fPtr

-- | A secret key of size 'cryptoSignSecretKeyBytes'.
--
-- @since 0.0.1.0
newtype SecretKey = SecretKey (ForeignPtr CUChar)
  deriving
    ( Display
      -- ^ @since 0.0.2.0
      -- > display secretKey == "[REDACTED]"
    )
    via (OpaqueInstance "[REDACTED]" SecretKey)

-- | > show secretKey == "[REDACTED]"
--
-- @since 0.0.2.0
instance Show SecretKey where
  show _ = "[REDACTED]"

-- |
--
-- @since 0.0.1.0
instance Eq SecretKey where
  (SecretKey sk1) == (SecretKey sk2) =
    unsafeDupablePerformIO $
      foreignPtrEq sk1 sk2 cryptoSignSecretKeyBytes

-- |
--
-- @since 0.0.1.0
instance Ord SecretKey where
  compare (SecretKey sk1) (SecretKey sk2) =
    unsafeDupablePerformIO $
      foreignPtrOrd sk1 sk2 cryptoSignSecretKeyBytes

-- | Convert a 'SecretKey' to a hexadecimal-encoded 'StrictByteString'.
--
-- ⚠️  Be prudent as to where you store it!
--
-- @since 0.0.2.0
unsafeSecretKeyToHexByteString :: SecretKey -> StrictByteString
unsafeSecretKeyToHexByteString (SecretKey secretKeyForeignPtr) =
  Base16.extractBase16 . Base16.encodeBase16' $
    ByteString.fromForeignPtr0
      (Foreign.castForeignPtr @CUChar @Word8 secretKeyForeignPtr)
      (fromIntegral @CSize @Int cryptoSignSecretKeyBytes)

-- | Create a 'SecretKey' from a binary 'StrictByteString' that you have obtained on your own,
-- usually from the network or disk.
--
-- The input secret key, once decoded from base16, must be of length
-- 'cryptoSignKeyBytes'.
--
-- @since 0.0.1.0
secretKeyFromHexByteString :: StrictByteString -> Either Text SecretKey
secretKeyFromHexByteString hexNonce = unsafeDupablePerformIO $
  case Base16.decodeBase16Untyped hexNonce of
    Right bytestring ->
      if ByteString.length bytestring == fromIntegral cryptoSignSecretKeyBytes
        then ByteString.unsafeUseAsCStringLen bytestring $ \(outsideSecretKeyPtr, _) ->
          fmap Right $
            newSecretKeyWith $ \secretKeyPtr ->
              Foreign.copyArray
                (Foreign.castPtr @CUChar @CChar secretKeyPtr)
                outsideSecretKeyPtr
                (fromIntegral cryptoSignSecretKeyBytes)
        else pure $ Left $ Text.pack "Secret Key is too short"
    Left msg -> pure $ Left msg

-- | Prepare memory for a 'SecretKey' and use the provided action to fill it.
--
-- Memory is allocated with 'LibSodium.Bindings.SecureMemory.sodiumMalloc' (see the note attached there).
-- A finalizer is run when the key is goes out of scope.
--
-- @since 0.0.2.0
newSecretKeyWith :: (Foreign.Ptr CUChar -> IO ()) -> IO SecretKey
newSecretKeyWith action = do
  ptr <- sodiumMalloc cryptoSignSecretKeyBytes
  when (ptr == Foreign.nullPtr) $ do
    throwErrno "sodium_malloc"
  fPtr <- Foreign.newForeignPtr finalizerSodiumFree ptr
  action ptr
  pure $ SecretKey fPtr

-- | A message and its signature.
-- The signature is of length 'cryptoSignBytes'.
--
-- @since 0.0.1.0
data SignedMessage = SignedMessage
  { messageLength :: CSize
  -- ^ Original message length
  , messageForeignPtr :: ForeignPtr CUChar
  , signatureForeignPtr :: ForeignPtr CUChar
  }

-- |
--
-- @since 0.0.1.0
instance Eq SignedMessage where
  (SignedMessage len1 msg1 sig1) == (SignedMessage len2 msg2 sig2) =
    unsafeDupablePerformIO $ do
      result1 <- foreignPtrEq msg1 msg2 len1
      result2 <- foreignPtrEq sig1 sig2 cryptoSignBytes
      return $ (len1 == len2) && result1 && result2

-- |
--
-- @since 0.0.1.0
instance Ord SignedMessage where
  compare (SignedMessage len1 msg1 sig1) (SignedMessage len2 msg2 sig2) =
    unsafeDupablePerformIO $ do
      result1 <- foreignPtrOrd msg1 msg2 len1
      result2 <- foreignPtrOrd sig1 sig2 cryptoSignBytes
      return $ compare len1 len2 <> result1 <> result2

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
            Just <$> ByteString.unsafePackMallocCStringLen (castPtr bsPtr :: Ptr CChar, fromIntegral messageLength)

-- | Get the signature part of a 'SignedMessage'.
--
-- @since 0.0.1.0
getSignature :: SignedMessage -> StrictByteString
getSignature SignedMessage{signatureForeignPtr} = unsafeDupablePerformIO $
  withForeignPtr signatureForeignPtr $ \signaturePtr -> do
    bsPtr <- Foreign.mallocBytes (fromIntegral cryptoSignBytes)
    memcpy bsPtr signaturePtr cryptoSignBytes
    ByteString.unsafePackMallocCStringLen (Foreign.castPtr bsPtr :: Ptr CChar, fromIntegral cryptoSignBytes)

-- | Get the message part of a 'SignedMessage' __without verifying the signature__.
--
-- @since 0.0.1.0
unsafeGetMessage :: SignedMessage -> StrictByteString
unsafeGetMessage SignedMessage{messageLength, messageForeignPtr} = unsafeDupablePerformIO $
  withForeignPtr messageForeignPtr $ \messagePtr -> do
    bsPtr <- Foreign.mallocBytes (fromIntegral messageLength)
    memcpy bsPtr messagePtr messageLength
    ByteString.unsafePackMallocCStringLen (Foreign.castPtr bsPtr :: Ptr CChar, fromIntegral messageLength)

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

-- |
-- @since 0.0.2.0
data PublicKeyExtractionException = PublicKeyExtractionException
  deriving stock
    ( Eq
      -- ^ @since 0.0.2.0
    , Ord
      -- ^ @since 0.0.2.0
    , Show
      -- ^ @since 0.0.2.0
    )
  deriving anyclass
    ( Exception
      -- ^ @since 0.0.2.0
    )
