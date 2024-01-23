{-# LANGUAGE DataKinds #-}
{-# LANGUAGE DerivingVia #-}
{-# LANGUAGE KindSignatures #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TypeApplications #-}

-- |
--
-- Module: Sel.SecretKey.Stream
-- Description: Encrypted Streams with ChaCha20Poly1305
-- Copyright: (C) Hécate Moonlight 2024
-- License: BSD-3-Clause
-- Maintainer: The Haskell Cryptography Group
-- Portability: GHC only
module Sel.SecretKey.Stream
  ( -- ** Introduction
    -- $introduction

    -- ** Usage
    -- $usage

    -- ** Stream operations
    Multipart
  , withMultipart
  , updateMultipart

    -- ** Secret Key
  , SecretKey
  , newSecretKey
  , secretKeyFromHexByteString
  , unsafeSecretKeyToHexByteString

    -- ** Ciphertext
  , Ciphertext
  , ciphertextFromHexByteString
  , ciphertextToBinary
  , ciphertextToHexByteString
  , ciphertextToHexText
  ) where

import Control.Monad.IO.Class (MonadIO)
import Data.ByteString (StrictByteString)
import Data.Kind (Type)
import Data.Text.Display (Display, OpaqueInstance)
import Foreign (ForeignPtr, Ptr)
import Foreign.C (CChar, CUChar, CULLong)
import LibSodium.Bindings.SecretStream (CryptoSecretStreamXChaCha20Poly1305State)

-- $introduction
-- This high-level API encrypts a sequence of messages, or a single message split into an arbitrary number of chunks, using a secret key, with the following properties:
--
-- * Messages cannot be truncated, removed, reordered, duplicated or modified without this being detected by the decryption functions.
-- * The same sequence encrypted twice will produce different ciphertexts.
-- * An authentication tag is added to each encrypted message: stream corruption will be detected early, without having to read the stream until the end.
-- * Each message can include additional data (ex: timestamp, protocol version) in the computation of the authentication tag.
-- * Messages can have different sizes.
-- * There are no practical limits to the total length of the stream, or to the total number of individual messages.

-- ** Hashing a multi-part message

-- | 'Multipart' is a cryptographic context for streaming hashing.
-- This API can be used when a message is too big to fit in memory or when the message is received in portions.
--
-- Use it like this:
--
-- >>> hash <- Stream.withMultipart $ \multipartState -> do -- we are in MonadIO
-- ...   message1 <- getMessage
-- ...   Stream.updateMultipart multipartState message1
-- ...   message2 <- getMessage
-- ...   Stream.updateMultipart multipartState message2
--
-- @since 0.0.1.0
newtype Multipart s = Multipart (Ptr CryptoSecretStreamXChaCha20Poly1305State)

type role Multipart nominal

-- | Perform streaming hashing with a 'Multipart' cryptographic context.
--
-- Use 'Stream.updateMultipart' within the continuation.
--
-- The context is safely allocated first, then the continuation is run
-- and then it is deallocated after that.
--
-- @since 0.0.1.0
withMultipart
  :: forall (a :: Type) (m :: Type -> Type)
   . MonadIO m
  => (forall s. Multipart s -> m a)
  -- ^ Continuation that gives you access to a 'Multipart' cryptographic context
  -> m Ciphertext
withMultipart actions = do
  allocateWith cryptoSecretStreamXChaCha20Poly1305StateBytes $ \statePtr -> do
    void $ liftIO $ cryptoSecretStreamXChaCha20Poly1305Init statePtr
    let part = Multipart statePtr
    actions part
    liftIO (finaliseMultipart part)

-- | Compute the 'Hash' of all the portions that were fed to the cryptographic context.
--
--  this function is only used within 'withMultipart'
--
--  @since 0.0.1.0
finaliseMultipart :: Multipart s -> IO Ciphertext
finaliseMultipart (Multipart statePtr) = do
  hashForeignPtr <- Foreign.mallocForeignPtrBytes (fromIntegral cryptoSecretStreamXChaCha20Poly1305Bytes)
  Foreign.withForeignPtr hashForeignPtr $ \(hashPtr :: Ptr CUChar) ->
    void $
      cryptoSecretStreamXChaCha20Poly1305Final
        statePtr
        hashPtr
  pure $ Hash hashForeignPtr

-- | Add a message portion to be hashed.
--
-- This function should be used within 'withMultipart'.
--
-- @since 0.0.1.0
updateMultipart :: Multipart s -> StrictByteString -> IO ()
updateMultipart (Multipart statePtr) message = do
  BS.unsafeUseAsCStringLen message $ \(cString, cStringLen) -> do
    let messagePtr = Foreign.castPtr @CChar @CUChar cString
    let messageLen = fromIntegral @Int @CULLong cStringLen
    void $
      cryptoSecretStreamXChaCha20Poly1305Update
        statePtr
        messagePtr
        messageLen

-- | A secret key of size 'cryptoSecretStreamXChaCha20Poly1305KeyBytes'.
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
      foreignPtrEq hk1 hk2 cryptoSecretStreamXChaCha20Poly1305KeyBytes

-- |
--
-- @since 0.0.1.0
instance Ord SecretKey where
  compare (SecretKey hk1) (SecretKey hk2) =
    unsafeDupablePerformIO $
      foreignPtrOrd hk1 hk2 cryptoSecretStreamXChaCha20Poly1305KeyBytes

-- | > show secretKey == "[REDACTED]"
--
-- @since 0.0.1.0
instance Show SecretKey where
  show _ = "[REDACTED]"

-- | Generate a new random secret key.
--
-- @since 0.0.1.0
newSecretKey :: IO SecretKey
newSecretKey = newSecretKeyWith cryptoSecretStreamXChaCha20Poly1305KeyGen

-- | Prepare memory for a 'SecretKey' and use the provided action to fill it.
--
-- Memory is allocated with 'LibSodium.Bindings.SecureMemory.sodiumMalloc' (see the note attached there).
-- A finalizer is run when the key is goes out of scope.
--
-- @since 0.0.1.0
newSecretKeyWith :: (Ptr CUChar -> IO ()) -> IO SecretKey
newSecretKeyWith action = do
  ptr <- sodiumMalloc cryptoSecretStreamXChaCha20Poly1305KeyBytes
  when (ptr == Foreign.nullPtr) $ do
    throwErrno "sodium_malloc"
  fPtr <- Foreign.newForeignPtr_ ptr
  Foreign.addForeignPtrFinalizer finalizerSodiumFree fPtr
  action ptr
  pure $ SecretKey fPtr

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
