{-# LANGUAGE DataKinds #-}
{-# LANGUAGE DerivingVia #-}
{-# LANGUAGE InstanceSigs #-}
{-# LANGUAGE KindSignatures #-}
{-# LANGUAGE RankNTypes #-}
{-# LANGUAGE RoleAnnotations #-}
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

import Control.Monad (void, when)
import Control.Monad.IO.Class (MonadIO)
import Data.ByteString (StrictByteString)
import qualified Data.ByteString.Internal as BS
import qualified Data.Text as Text
import qualified Data.ByteString as BS
import qualified Data.ByteString.Base16 as Base16
import qualified Data.Base16.Types as Base16
import qualified Data.ByteString.Unsafe as BS
import Data.Kind (Type)
import Data.Text.Display (Display (..), OpaqueInstance (..))
import qualified Data.Text.Lazy.Builder as Builder
import Foreign (ForeignPtr, Ptr, Storable (..))
import qualified Foreign
import Foreign.C (CChar, CUChar, CULLong, CSize)
import qualified Foreign.ForeignPtr as Foreign
import qualified Foreign.Ptr as Foreign

import LibSodium.Bindings.SecretStream
import Data.Text (Text)
import Data.Word

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
  pure $ Ciphertext hashForeignPtr

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

-- | Create a 'SecretKey' from a hexadecimal-encoded 'StrictByteString' that you have obtained on your own,
-- usually from the network or disk.
--
-- The input secret key, once decoded from base16, must be of length
-- 'cryptoSecretStreamXChaCha20Poly1305KeyBytes'.
--
-- @since 0.0.1.0
secretKeyFromHexByteString :: StrictByteString -> Either Text SecretKey
secretKeyFromHexByteString hexSecretKey = unsafeDupablePerformIO $
  case Base16.decodeBase16Untyped hexSecretKey of
    Right bytestring ->
      if BS.length bytestring == fromIntegral cryptoSecretStreamXChaCha20Poly1305KeyBytes
        then BS.unsafeUseAsCStringLen bytestring $ \(outsideSecretKeyPtr, _) ->
          fmap Right $
            newSecretKeyWith $ \secretKeyPtr ->
              Foreign.copyArray
                (Foreign.castPtr @CUChar @CChar secretKeyPtr)
                outsideSecretKeyPtr
                (fromIntegral cryptoSecretStreamXChaCha20Poly1305KeyBytes)
        else pure $ Left $ Text.pack "Secret Key is too short"
    Left msg -> pure $ Left msg

-- | Convert a 'SecretKey' to a hexadecimal-encoded 'StrictByteString'.
--
-- ⚠️  Be prudent as to where you store it!
--
-- @since 0.0.1.0
unsafeSecretKeyToHexByteString :: SecretKey -> StrictByteString
unsafeSecretKeyToHexByteString (SecretKey secretKeyForeignPtr) =
  Base16.extractBase16 . Base16.encodeBase16' $
    BS.fromForeignPtr0
      (Foreign.castForeignPtr @CUChar @Word8 secretKeyForeignPtr)
      (fromIntegral @CSize @Int cryptoSecretStreamXChaCha20Poly1305KeyBytes)


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
newtype Ciphertext = Ciphertext (ForeignPtr CUChar)

-- |
--
-- @since 0.0.1.0
instance Eq Ciphertext where
  (Ciphertext h1) == (Ciphertext h2) =
    unsafeDupablePerformIO $
      foreignPtrEq h1 h2 cryptoHashSHA256Bytes

-- |
--
-- @since 0.0.1.0
instance Ord Ciphertext where
  compare (Ciphertext h1) (Ciphertext h2) =
    unsafeDupablePerformIO $
      foreignPtrOrd h1 h2 cryptoHashSHA256Bytes

-- |
--
-- @since 0.0.1.0
instance Storable Ciphertext where
  sizeOf :: Ciphertext -> Int
  sizeOf _ = fromIntegral cryptoHashSHA256Bytes

  --  Aligned on the size of 'cryptoHashSHA256Bytes'
  alignment :: Ciphertext -> Int
  alignment _ = 32

  poke :: Ptr Ciphertext -> Ciphertext -> IO ()
  poke ptr (Ciphertext hashForeignPtr) =
    Foreign.withForeignPtr hashForeignPtr $ \hashPtr ->
      Foreign.copyArray (Foreign.castPtr ptr) hashPtr (fromIntegral cryptoHashSHA256Bytes)

  peek :: Ptr Ciphertext -> IO Ciphertext
  peek ptr = do
    hashfPtr <- Foreign.mallocForeignPtrBytes (fromIntegral cryptoHashSHA256Bytes)
    Foreign.withForeignPtr hashfPtr $ \hashPtr ->
      Foreign.copyArray hashPtr (Foreign.castPtr ptr) (fromIntegral cryptoHashSHA256Bytes)
    pure $ Ciphertext hashfPtr

-- |
--
-- @since 0.0.1.0
instance Display Ciphertext where
  displayBuilder = Builder.fromText . hashToHexText

-- |
--
-- @since 0.0.1.0
instance Show Ciphertext where
  show = BS.unpackChars . hashToHexByteString

ciphertextFromHexByteString :: StrictByteString -> Either Text Ciphertext
ciphertextFromHexByteString hexCiphertext = unsafeDupablePerformIO $
  case Base16.decodeBase16Untyped hexHash of
    Right bytestring ->
      if BS.length bytestring >= fromIntegral cryptoSecretboxMACBytes
        then BS.unsafeUseAsCStringLen bytestring $ \(outsideHashPtr, outsideHashLength) -> do
          hashForeignPtr <- BS.mallocByteString @CChar outsideHashLength -- The foreign pointer that will receive the hash data.
          Foreign.withForeignPtr hashForeignPtr $ \hashPtr ->
            -- We copy bytes from 'outsideHashPtr' to 'hashPtr'.
            Foreign.copyArray hashPtr outsideHashPtr outsideHashLength
          pure $
            Right $
              Hash
                (fromIntegral @Int @CULLong outsideHashLength - fromIntegral @CSize @CULLong cryptoSecretboxMACBytes)
                (Foreign.castForeignPtr @CChar @CUChar hashForeignPtr)
        else pure $ Left $ Text.pack "Hash is too short"
    Left msg -> pure $ Left msg
-- ciphertextToBinary
-- ciphertextToHexByteString
-- ciphertextToHexText
