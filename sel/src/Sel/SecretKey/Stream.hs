{-# LANGUAGE DataKinds #-}
{-# LANGUAGE DerivingVia #-}
{-# LANGUAGE KindSignatures #-}
{-# LANGUAGE LambdaCase #-}
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

    -- *** Stream Encryption
  , encryptStream
  , encryptChunk

    -- *** Stream Decryption
  , decryptStream
  , decryptChunk

    -- ** Secret Key
  , SecretKey
  , newSecretKey
  , secretKeyFromHexByteString
  , unsafeSecretKeyToHexByteString

    -- ** Header
  , Header
  , headerToHexByteString

    -- ** Message Tags
  , MessageTag (..)

    -- ** CipherText
  , CipherText
  , ciphertextFromHexByteString
  , ciphertextToBinary
  , ciphertextToHexByteString
  , ciphertextToHexText
  ) where

import Control.Monad (void, when)
import Control.Monad.IO.Class (MonadIO, liftIO)
import qualified Data.Base16.Types as Base16
import Data.ByteString (StrictByteString)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Base16 as Base16
import qualified Data.ByteString.Internal as BS
import qualified Data.ByteString.Unsafe as BS
import Data.Kind (Type)
import Data.Text (Text)
import qualified Data.Text as Text
import Data.Text.Display (Display (..), OpaqueInstance (..))
import qualified Data.Text.Lazy.Builder as Builder
import Data.Word (Word8)
import Foreign (ForeignPtr, Ptr)
import qualified Foreign
import Foreign.C (CChar, CSize, CUChar, CULLong)
import Foreign.C.Error (throwErrno)
import System.IO.Unsafe (unsafeDupablePerformIO)

import LibSodium.Bindings.SecretStream
  ( CryptoSecretStreamXChaCha20Poly1305State
  , cryptoSecretStreamXChaCha20Poly1305ABytes
  , cryptoSecretStreamXChaCha20Poly1305HeaderBytes
  , cryptoSecretStreamXChaCha20Poly1305InitPull
  , cryptoSecretStreamXChaCha20Poly1305InitPush
  , cryptoSecretStreamXChaCha20Poly1305KeyBytes
  , cryptoSecretStreamXChaCha20Poly1305KeyGen
  , cryptoSecretStreamXChaCha20Poly1305Pull
  , cryptoSecretStreamXChaCha20Poly1305Push
  , cryptoSecretStreamXChaCha20Poly1305StateBytes
  , cryptoSecretStreamXChaCha20Poly1305TagFinal
  , cryptoSecretStreamXChaCha20Poly1305TagMessage
  , cryptoSecretStreamXChaCha20Poly1305TagPush
  , cryptoSecretStreamXChaCha20Poly1305TagRekey
  )
import LibSodium.Bindings.SecureMemory (finalizerSodiumFree, sodiumMalloc)
import Sel.Internal (allocateWith, foreignPtrEq, foreignPtrOrd)

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

-- | 'Multipart' is the cryptographic context for stream encryption.
--
-- Use it like this:
--
-- >>>
-- >>> hash <- Stream.encryptStream $ \multipartState -> do -- we are in MonadIO
-- ...   message1 <- getMessage -- This is your way to fetch a message from outside
-- ...   Stream.encryptChunk multipartState message1
-- ...   message2 <- getMessage
-- ...   Stream.encryptChunk multipartState message2
--
-- @since 0.0.1.0
newtype Multipart s = Multipart (Ptr CryptoSecretStreamXChaCha20Poly1305State)

type role Multipart nominal

-- | Perform streaming hashing with a 'Multipart' cryptographic context.
--
-- Use 'Stream.encryptChunk' within the continuation.
--
-- The context is safely allocated first, then the continuation is run
-- and then it is deallocated after that.
--
-- @since 0.0.1.0
encryptStream
  :: forall (a :: Type) (m :: Type -> Type)
   . MonadIO m
  => SecretKey
  -- ^ Generated with 'newSecretKey'.
  -> (forall s. Multipart s -> m a)
  -- ^ Continuation that gives you access to a 'Multipart' cryptographic context
  -> m (Header, a)
encryptStream (SecretKey secretKeyForeignPtr) actions = allocateWith cryptoSecretStreamXChaCha20Poly1305StateBytes $ \statePtr -> do
  headerPtr <- liftIO $ sodiumMalloc cryptoSecretStreamXChaCha20Poly1305HeaderBytes
  when (headerPtr == Foreign.nullPtr) $
    liftIO $
      throwErrno "sodium_malloc"
  headerForeignPtr <- liftIO $ Foreign.newForeignPtr finalizerSodiumFree headerPtr
  liftIO $ Foreign.withForeignPtr secretKeyForeignPtr $ \secretKeyPtr ->
    void $
      cryptoSecretStreamXChaCha20Poly1305InitPush
        statePtr
        headerPtr
        secretKeyPtr
  let part = Multipart statePtr
  let header = Header headerForeignPtr
  result <- actions part
  pure (header, result)

-- | Add a message portion (/chunk/) to be encrypted.
--
-- Use this function within 'encryptStream'.
--
-- @since 0.0.1.0
encryptChunk
  :: MonadIO m
  => Multipart s
  -- ^ Cryptographic context
  -> MessageTag
  -- ^ Tag that will be associated with the message. See the documentation of 'MessageTag' to know which to choose when.
  -> StrictByteString
  -- ^ Message to encrypt.
  -> m CipherText
encryptChunk (Multipart statePtr) messageTag message = liftIO $ BS.unsafeUseAsCStringLen message $ \(cString, cStringLen) -> do
  cipherTextFPtr <- Foreign.mallocForeignPtrBytes (cStringLen + fromIntegral cryptoSecretStreamXChaCha20Poly1305ABytes)
  Foreign.withForeignPtr cipherTextFPtr $ \cipherTextPtr -> do
    let messagePtr = Foreign.castPtr @CChar @CUChar cString
    let messageLen = fromIntegral @Int @CULLong cStringLen
    void $
      cryptoSecretStreamXChaCha20Poly1305Push
        statePtr
        cipherTextPtr
        Foreign.nullPtr
        messagePtr
        messageLen
        Foreign.nullPtr
        0
        (messageTagToConstant messageTag)
  pure $ CipherText (fromIntegral cStringLen) cipherTextFPtr

-- | Perform streaming decryption with a 'Multipart' cryptographic context.
--
-- Use 'Stream.decryptChunk' within the continuation.
--
-- The context is safely allocated first, then the continuation is run
-- and then it is deallocated after that.
--
-- @since 0.0.1.0
decryptStream
  :: forall (a :: Type) (m :: Type -> Type)
   . MonadIO m
  => SecretKey
  -> Header
  -- ^ Header used by the encrypting party. See its documentation
  -> (forall s. Multipart s -> m a)
  -- ^ Continuation that gives you access to a 'Multipart' cryptographic context
  -> m (Maybe a)
decryptStream (SecretKey secretKeyForeignPtr) (Header headerForeignPtr) actions = allocateWith cryptoSecretStreamXChaCha20Poly1305StateBytes $ \statePtr -> do
  result <- liftIO $ Foreign.withForeignPtr secretKeyForeignPtr $ \secretKeyPtr -> do
    Foreign.withForeignPtr headerForeignPtr $ \headerPtr -> do
      cryptoSecretStreamXChaCha20Poly1305InitPull
        statePtr
        headerPtr
        secretKeyPtr
  if result /= 0
    then pure Nothing
    else do
      let part = Multipart statePtr
      Just <$> actions part

-- | Add a message portion (/chunk/) to be decrypted.
--
-- Use this function within 'decryptStream'.
--
-- @since 0.0.1.0
decryptChunk
  :: MonadIO m
  => Multipart s
  -- ^ Cryptographic context
  -> StrictByteString
  -- ^ Message portion to decrypt
  -> m StrictByteString
decryptChunk (Multipart statePtr) message = do
  let clearTextLen = fromIntegral (BS.length message) - cryptoSecretStreamXChaCha20Poly1305ABytes
  clearTextBuffer <- liftIO $ sodiumMalloc clearTextLen
  clearTextForeignPtr <- liftIO $ Foreign.newForeignPtr finalizerSodiumFree clearTextBuffer
  liftIO $ BS.unsafeUseAsCStringLen message $ \(cipherTextBuffer, cipherTextLen) -> do
    tagBuffer <- sodiumMalloc 1
    void $
      cryptoSecretStreamXChaCha20Poly1305Pull
        statePtr
        clearTextBuffer
        Foreign.nullPtr
        tagBuffer
        (Foreign.castPtr @CChar @CUChar cipherTextBuffer)
        (fromIntegral @Int @CULLong cipherTextLen)
        Foreign.nullPtr
        0
  pure $
    BS.fromForeignPtr0
      (Foreign.castForeignPtr @CUChar @Word8 clearTextForeignPtr)
      (fromIntegral @CSize @Int clearTextLen)

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

-- | Create a 'SecretKey' from a binary 'StrictByteString' that you have obtained on your own,
-- usually from the network or disk.
--
-- The input secret key, once decoded from base16, must be of length
-- 'cryptoSecretStreamXChaCha20Poly1305KeyBytes'.
--
-- @since 0.0.1.0
secretKeyFromHexByteString :: StrictByteString -> Either Text SecretKey
secretKeyFromHexByteString hexNonce = unsafeDupablePerformIO $
  case Base16.decodeBase16Untyped hexNonce of
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

-- Prepare memory for a 'SecretKey' and use the provided action to fill it.
--
-- Memory is allocated with 'LibSodium.Bindings.SecureMemory.sodiumMalloc' (see the note attached there).
-- A finalizer is run when the key is goes out of scope.
--
-- @since 0.0.1.0
newSecretKeyWith :: (Ptr CUChar -> IO ()) -> IO SecretKey
newSecretKeyWith action = do
  ptr <- sodiumMalloc cryptoSecretStreamXChaCha20Poly1305KeyBytes
  when (ptr == Foreign.nullPtr) $ throwErrno "sodium_malloc"
  fPtr <- Foreign.newForeignPtr_ ptr
  Foreign.addForeignPtrFinalizer finalizerSodiumFree fPtr
  action ptr
  pure $ SecretKey fPtr

-- | An encrypted stream starts with a 'Header' of size 'cryptoSecretStreamXChaCha20Poly1305HeaderBytes'.
--
-- That header must be sent/stored before the sequence of encrypted messages, as it is required to decrypt the stream.
--
-- The header content doesn’t have to be secret and decryption with a different header will fail.
newtype Header = Header (ForeignPtr CUChar)

-- | @since 0.0.1.0
instance Show Header where
  show = BS.unpackChars . headerToHexByteString

instance Display Header where
  displayBuilder = Builder.fromText . headerToHexText

-- |
--
-- @since 0.0.1.0
instance Eq Header where
  (Header header1) == (Header header2) =
    unsafeDupablePerformIO $
      foreignPtrEq header1 header2 cryptoSecretStreamXChaCha20Poly1305HeaderBytes

-- |
--
-- @since 0.0.1.0
instance Ord Header where
  compare (Header header1) (Header header2) =
    unsafeDupablePerformIO $
      foreignPtrOrd header1 header2 cryptoSecretStreamXChaCha20Poly1305HeaderBytes

-- | Convert a 'Header' to a hexadecimal-encoded 'StrictByteString'
--
-- @since 0.0.1.0
headerToHexByteString :: Header -> StrictByteString
headerToHexByteString (Header headerForeignPtr) =
  Base16.extractBase16 . Base16.encodeBase16' $
    BS.fromForeignPtr0
      (Foreign.castForeignPtr @CUChar @Word8 headerForeignPtr)
      (fromIntegral @CSize @Int cryptoSecretStreamXChaCha20Poly1305HeaderBytes)

-- | Convert a 'Header' to a hexadecimal-encoded 'Text'.
--
-- @since 0.0.1.0
headerToHexText :: Header -> Text
headerToHexText = Base16.extractBase16 . Base16.encodeBase16 . headerToHexByteString

-- | Each encrypted message is associated with a tag.
--
-- A typical encrypted stream simply attaches 'Message' as a tag to all messages,
-- except the last one which is tagged as 'Final'.
--
-- @since 0.0.1.0
data MessageTag
  = -- | The most common tag, that doesn’t add any information about the nature of the message.
    Message
  | -- | Indicates that the message marks the end of the stream, and erases the secret key used to encrypt the previous sequence.
    Final
  | -- | Indicates that the message marks the end of a set of messages, but not the end of the stream.
    Push
  | -- | “Forget” the key used to encrypt this message and the previous ones, and derive a new secret key.
    Rekey

-- | Convert a 'MessageTag' to its corresponding constant.
--
-- @since 0.0.1.0
messageTagToConstant :: MessageTag -> CUChar
messageTagToConstant = \case
  Message -> fromIntegral cryptoSecretStreamXChaCha20Poly1305TagMessage
  Final -> fromIntegral cryptoSecretStreamXChaCha20Poly1305TagFinal
  Push -> fromIntegral cryptoSecretStreamXChaCha20Poly1305TagPush
  Rekey -> fromIntegral cryptoSecretStreamXChaCha20Poly1305TagRekey

-- | An encrypted message. It is guaranteed to be of size:
--  @original_message_length + 'cryptoSecretStreamXChaCha20Poly1305ABytes'@
--
-- @since 0.0.1.0
data CipherText = CipherText
  { messageLength :: CULLong
  , cipherTextForeignPtr :: ForeignPtr CUChar
  }

-- |
--
-- @since 0.0.1.0
instance Eq CipherText where
  (CipherText cipherTextLength1 h1) == (CipherText cipherTextLength2 h2) =
    unsafeDupablePerformIO $ do
      result1 <-
        foreignPtrEq
          h1
          h2
          (fromIntegral cipherTextLength1 + cryptoSecretStreamXChaCha20Poly1305ABytes)
      pure $ cipherTextLength1 == cipherTextLength2 && result1

-- |
--
-- @since 0.0.1.0
instance Ord CipherText where
  compare (CipherText cipherTextLength1 c1) (CipherText cipherTextLength2 c2) =
    unsafeDupablePerformIO $ do
      result1 <- foreignPtrOrd c1 c2 (fromIntegral cipherTextLength1 + cryptoSecretStreamXChaCha20Poly1305ABytes)
      pure $ compare cipherTextLength1 cipherTextLength2 <> result1

-- |
--
-- @since 0.0.1.0
instance Display CipherText where
  displayBuilder = Builder.fromText . ciphertextToHexText

-- |
--
-- @since 0.0.1.0
instance Show CipherText where
  show = BS.unpackChars . ciphertextToHexByteString

-- | Create a 'CipherText' from a binary 'StrictByteString' that you have obtained on your own,
-- usually from the network or disk. It must be a valid hash built from the concatenation
-- of the encrypted message and the authentication tag.
--
-- The input hash must at least of length 'cryptoSecretStreamXChaCha20Poly1305ABytes'
--
-- @since 0.0.1.0
ciphertextFromHexByteString :: StrictByteString -> Either Text CipherText
ciphertextFromHexByteString hexCipherText = unsafeDupablePerformIO $
  case Base16.decodeBase16Untyped hexCipherText of
    Right bytestring ->
      if BS.length bytestring >= fromIntegral cryptoSecretStreamXChaCha20Poly1305ABytes
        then BS.unsafeUseAsCStringLen bytestring $ \(outsideCipherTextPtr, outsideCipherTextLength) -> do
          hashForeignPtr <- BS.mallocByteString @CChar outsideCipherTextLength -- The foreign pointer that will receive the hash data.
          Foreign.withForeignPtr hashForeignPtr $ \hashPtr ->
            -- We copy bytes from 'outsideCipherTextPtr' to 'hashPtr'.
            Foreign.copyArray hashPtr outsideCipherTextPtr outsideCipherTextLength
          pure $
            Right $
              CipherText
                (fromIntegral @Int @CULLong outsideCipherTextLength - fromIntegral @CSize @CULLong cryptoSecretStreamXChaCha20Poly1305ABytes)
                (Foreign.castForeignPtr @CChar @CUChar hashForeignPtr)
        else pure $ Left $ Text.pack "CipherText is too short"
    Left msg -> pure $ Left msg

-- | Convert a 'CipherText' to a hexadecimal-encoded 'Text'.
--
-- ⚠️  Be prudent as to where you store it!
--
-- @since 0.0.1.0
ciphertextToHexText :: CipherText -> Text
ciphertextToHexText = Base16.extractBase16 . Base16.encodeBase16 . ciphertextToBinary

-- | Convert a 'CipherText' to a hexadecimal-encoded 'StrictByteString'.
--
-- ⚠️  Be prudent as to where you store it!
--
-- @since 0.0.1.0
ciphertextToHexByteString :: CipherText -> StrictByteString
ciphertextToHexByteString = Base16.extractBase16 . Base16.encodeBase16' . ciphertextToBinary

-- | Convert a 'CipherText' to a binary 'StrictByteString'.
--
-- ⚠️  Be prudent as to where you store it!
--
-- @since 0.0.1.0
ciphertextToBinary :: CipherText -> StrictByteString
ciphertextToBinary (CipherText cipherTextLength fPtr) =
  BS.fromForeignPtr0
    (Foreign.castForeignPtr fPtr)
    (fromIntegral cipherTextLength + fromIntegral cryptoSecretStreamXChaCha20Poly1305ABytes)
