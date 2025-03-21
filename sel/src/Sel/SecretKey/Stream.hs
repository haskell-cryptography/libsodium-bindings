{-# LANGUAGE DataKinds #-}
{-# LANGUAGE DeriveAnyClass #-}
{-# LANGUAGE DerivingVia #-}
{-# LANGUAGE KindSignatures #-}
{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE NamedFieldPuns #-}
{-# LANGUAGE RankNTypes #-}
{-# LANGUAGE RoleAnnotations #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TypeApplications #-}

-- |
--
-- Module: Sel.SecretKey.Stream
-- Description: Encrypted Streams with XChaCha20-Poly1305
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

    -- *** Linked List operations
    encryptList
  , decryptList

    -- *** Chunk operations
  , Multipart
  , encryptStream
  , encryptChunk
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
  , headerFromHexByteString

    -- ** Message Tags
  , MessageTag (..)

    -- ** Additional data (AD)
  , AdditionalData (..)
  , AdditionalDataHexDecodingError (..)
  , additionalDataFromHexByteString
  , additionalDataToBinary
  , additionalDataToHexByteString
  , additionalDataToHexText

    -- ** Ciphertext
  , Ciphertext
  , ciphertextFromHexByteString
  , ciphertextToBinary
  , ciphertextToHexByteString
  , ciphertextToHexText

    -- ** Exceptions
  , StreamInitEncryptionException
  , StreamEncryptionException
  , StreamDecryptionException
  ) where

import Control.Exception (Exception, throw)
import Control.Monad (forM, when)
import Control.Monad.IO.Class (MonadIO, liftIO)
import Data.Base16.Types (Base16)
import qualified Data.Base16.Types as Base16
import Data.ByteString (StrictByteString)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Base16 as Base16
import qualified Data.ByteString.Internal as BSI
import qualified Data.ByteString.Unsafe as BSU
import Data.Kind (Type)
import qualified Data.List as List
import Data.Text (Text)
import qualified Data.Text as Text
import qualified Data.Text.Builder.Linear as Builder
import Data.Text.Display (Display (..), OpaqueInstance (..), ShowInstance (..))
import Foreign (ForeignPtr, Ptr)
import qualified Foreign
import Foreign.C (CChar, CSize, CUChar, CULLong)
import Foreign.C.Error (throwErrno)
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
import System.IO.Unsafe (unsafeDupablePerformIO)

import Sel.Internal (allocateWith, foreignPtrEq, foreignPtrOrd)
import Sel.Internal.Sodium (binaryToHex)

-- $introduction
-- This high-level API encrypts a sequence of messages, or a single message split into an arbitrary number of chunks, using a secret key, with the following properties:
--
-- * Messages cannot be truncated, removed, reordered, duplicated or modified without this being detected by the decryption functions.
-- * The same sequence encrypted twice will produce different ciphertexts.
-- * An authentication tag is added to each encrypted message: stream corruption will be detected early, without having to read the stream until the end.
-- * Each message can include additional data (ex: timestamp, protocol version) in the computation of the authentication tag.
-- * Messages can have different sizes.
-- * There are no practical limits to the total length of the stream, or to the total number of individual messages.
--
-- It uses the [XChaCha20-Poly1305 algorithm](https://en.wikipedia.org/wiki/ChaCha20-Poly1305).

-- $usage
--
-- >>> secretKey <- Stream.newSecretKey
-- >>> (header, ciphertexts) <- Stream.encryptStream secretKey $ \multipartState -> do -- we are in MonadIO
-- ...   message1 <- getMessage -- This is your way to fetch a message from outside
-- ...   encryptedChunk1 <- Stream.encryptChunk multipartState Stream.messag message1
-- ...   message2 <- getMessage
-- ...   encryptedChunk2 <- Stream.encryptChunk multipartState Stream.Final message2
-- ...   pure [encryptedChunk1, encryptedChunk2]
-- >>> result <- Stream.decryptStream secretKey header $ \multipartState-> do
-- ...    forM encryptedMessages $ \ciphertext -> do
-- ...      decryptChunk multipartState ciphertext

-- | 'Multipart' is the cryptographic context for stream encryption.
--
-- @since 0.0.1.0
newtype Multipart s = Multipart (Ptr CryptoSecretStreamXChaCha20Poly1305State)

type role Multipart nominal

-- | Perform streaming encryption with a 'Multipart' cryptographic context.
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
  headerForeignPtr <- liftIO $ Foreign.newForeignPtr finalizerSodiumFree headerPtr
  when (headerPtr == Foreign.nullPtr) $ liftIO (throwErrno "sodium_malloc")
  liftIO $ Foreign.withForeignPtr secretKeyForeignPtr $ \secretKeyPtr -> do
    result <-
      cryptoSecretStreamXChaCha20Poly1305InitPush
        statePtr
        headerPtr
        secretKeyPtr
    when (result /= 0) $ throw StreamInitEncryptionException
  let part = Multipart statePtr
  let header = Header headerForeignPtr
  result <- actions part
  pure (header, result)

-- | Add a message portion (/chunk/) to be encrypted.
--
-- Use it within 'encryptStream'.
--
-- This function can throw 'StreamEncryptionException' upon an error in the underlying implementation.
--
-- @since 0.0.1.0
encryptChunk
  :: forall m s
   . MonadIO m
  => Multipart s
  -- ^ Cryptographic context
  -> MessageTag
  -- ^ Tag that will be associated with the message. See the documentation of 'MessageTag' to know which to choose when.
  -> Maybe AdditionalData
  -- ^ Additional data (AD) to be authenticated.
  -> StrictByteString
  -- ^ Message to encrypt.
  -> m Ciphertext
encryptChunk (Multipart statePtr) messageTag mbAd message = liftIO $
  BSU.unsafeUseAsCStringLen message $ \(messageCString, messageCStringLen) ->
    BSU.unsafeUseAsCStringLen (maybe BS.empty additionalDataToBinary mbAd) $ \(adCString, adCStringLen) -> do
      let messagePtr = Foreign.castPtr @CChar @CUChar messageCString
          messageLen = fromIntegral @Int @CULLong messageCStringLen
          adPtr = Foreign.castPtr @CChar @CUChar adCString
          adLen = fromIntegral @Int @CULLong adCStringLen
      ciphertextFPtr <- Foreign.mallocForeignPtrBytes (messageCStringLen + fromIntegral cryptoSecretStreamXChaCha20Poly1305ABytes)
      Foreign.withForeignPtr ciphertextFPtr $ \ciphertextBuffer -> do
        result <-
          cryptoSecretStreamXChaCha20Poly1305Push
            statePtr
            ciphertextBuffer
            Foreign.nullPtr -- default size of messageLen + 'cryptoSecretStreamXChaCha20Poly1305ABytes'
            messagePtr
            messageLen
            adPtr
            adLen
            (messageTagToConstant messageTag)
        when (result /= 0) $ throw StreamEncryptionException
      pure $ Ciphertext (fromIntegral messageCStringLen) ciphertextFPtr

-- | Perform streaming encryption of a finite list.
--
-- This function can throw 'StreamEncryptionException' upon an error in the underlying implementation.
--
-- @since 0.0.1.0
encryptList :: forall m. MonadIO m => SecretKey -> [(Maybe AdditionalData, StrictByteString)] -> m (Header, [Ciphertext])
encryptList secretKey messages = encryptStream secretKey $ \multipart -> go multipart messages []
  where
    go :: Multipart s -> [(Maybe AdditionalData, StrictByteString)] -> [Ciphertext] -> m [Ciphertext]
    go multipart [(mbLastAd, lastMsg)] acc = do
      encryptedChunk <- encryptChunk multipart Final mbLastAd lastMsg
      pure $ List.reverse $ encryptedChunk : acc
    go multipart ((mbAd, msg) : rest) acc = do
      encryptedChunk <- encryptChunk multipart Message mbAd msg
      go multipart rest (encryptedChunk : acc)
    go _ [] acc = pure acc

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
-- This function can throw 'StreamDecryptionException' if the chunk is invalid, incomplete, or corrupted.
--
-- @since 0.0.1.0
decryptChunk
  :: forall m s
   . MonadIO m
  => Multipart s
  -- ^ Cryptographic context
  -> Maybe AdditionalData
  -- ^ Additional data (AD) to be authenticated.
  -> Ciphertext
  -- ^ Encrypted message portion to decrypt
  -> m StrictByteString
  -- ^ Decrypted message portion
decryptChunk (Multipart statePtr) mbAd Ciphertext{messageLength, ciphertextForeignPtr} = do
  clearTextForeignPtr <- liftIO $ Foreign.mallocForeignPtrBytes (fromIntegral messageLength)
  let ciphertextLen = messageLength + fromIntegral cryptoSecretStreamXChaCha20Poly1305ABytes
  liftIO $ Foreign.withForeignPtr ciphertextForeignPtr $ \ciphertextBuffer -> do
    BSU.unsafeUseAsCStringLen (maybe BS.empty additionalDataToBinary mbAd) $ \(adCString, adCStringLen) -> do
      let adPtr = Foreign.castPtr @CChar @CUChar adCString
          adLen = fromIntegral @Int @CULLong adCStringLen
      liftIO $ Foreign.withForeignPtr clearTextForeignPtr $ \clearTextBuffer -> do
        tagBuffer <- sodiumMalloc 1
        result <-
          cryptoSecretStreamXChaCha20Poly1305Pull
            statePtr
            clearTextBuffer
            Foreign.nullPtr
            tagBuffer
            ciphertextBuffer
            ciphertextLen
            adPtr
            adLen
        when (result /= 0) $ throw StreamDecryptionException
        bsPtr <- Foreign.mallocBytes (fromIntegral messageLength)
        Foreign.copyBytes bsPtr (Foreign.castPtr clearTextBuffer) (fromIntegral messageLength)
        BSU.unsafePackMallocCStringLen (bsPtr, fromIntegral messageLength)

-- | Perform streaming decryption of a finite Linked List.
--
-- This function can throw 'StreamDecryptionException' if the chunk is invalid, incomplete, or corrupted.
--
-- @since 0.0.1.0
decryptList :: forall m. MonadIO m => SecretKey -> Header -> [(Maybe AdditionalData, Ciphertext)] -> m (Maybe [StrictByteString])
decryptList secretKey header encryptedMessages =
  decryptStream secretKey header $ \multipart -> do
    forM encryptedMessages $ \(mbAd, ciphertext) -> do
      decryptChunk multipart mbAd ciphertext

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

-- | @since 0.0.1.0
instance Eq SecretKey where
  (SecretKey hk1) == (SecretKey hk2) =
    foreignPtrEq hk1 hk2 cryptoSecretStreamXChaCha20Poly1305KeyBytes

-- | @since 0.0.1.0
instance Ord SecretKey where
  compare (SecretKey hk1) (SecretKey hk2) =
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
secretKeyFromHexByteString :: Base16 StrictByteString -> Either Text SecretKey
secretKeyFromHexByteString hexSecretKey = unsafeDupablePerformIO $
  case Base16.decodeBase16Untyped (Base16.extractBase16 hexSecretKey) of
    Right bytestring ->
      if BS.length bytestring == fromIntegral cryptoSecretStreamXChaCha20Poly1305KeyBytes
        then BSU.unsafeUseAsCStringLen bytestring $ \(outsideSecretKeyPtr, _) -> do
          secretKey <- newSecretKeyWith $ \secretKeyPtr ->
            Foreign.copyArray
              (Foreign.castPtr @CUChar @CChar secretKeyPtr)
              outsideSecretKeyPtr
              (fromIntegral cryptoSecretStreamXChaCha20Poly1305KeyBytes)
          pure $ Right secretKey
        else pure $ Left $ Text.pack ("Secret Key is not of size " <> show cryptoSecretStreamXChaCha20Poly1305KeyBytes)
    Left msg -> pure $ Left msg

-- | Convert a 'SecretKey' to a hexadecimal-encoded 'StrictByteString' in constant time.
--
-- ⚠️  Be prudent as to where you store it!
--
-- @since 0.0.1.0
unsafeSecretKeyToHexByteString :: SecretKey -> Base16 StrictByteString
unsafeSecretKeyToHexByteString (SecretKey secretKeyForeignPtr) =
  Base16.assertBase16 $ binaryToHex secretKeyForeignPtr cryptoSecretStreamXChaCha20Poly1305KeyBytes

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
  fPtr <- Foreign.newForeignPtr finalizerSodiumFree ptr
  action ptr
  pure $ SecretKey fPtr

-- | An encrypted stream starts with a 'Header' of size 'cryptoSecretStreamXChaCha20Poly1305HeaderBytes'.
--
-- That header must be sent/stored before the sequence of encrypted messages, as it is required to decrypt the stream.
--
-- The header content doesn’t have to be secret and decryption with a different header will fail.
--
-- @since 0.0.1.0
newtype Header = Header (ForeignPtr CUChar)

-- | @since 0.0.1.0
instance Show Header where
  show = BSI.unpackChars . Base16.extractBase16 . headerToHexByteString

-- | @since 0.0.1.0
instance Display Header where
  displayBuilder = Builder.fromText . Base16.extractBase16 . headerToHexText

-- | @since 0.0.1.0
instance Eq Header where
  (Header header1) == (Header header2) =
    foreignPtrEq header1 header2 cryptoSecretStreamXChaCha20Poly1305HeaderBytes

-- | @since 0.0.1.0
instance Ord Header where
  compare (Header header1) (Header header2) =
    foreignPtrOrd header1 header2 cryptoSecretStreamXChaCha20Poly1305HeaderBytes

-- | Convert a 'Header' to a hexadecimal-encoded 'StrictByteString' in constant time.
--
-- @since 0.0.1.0
headerToHexByteString :: Header -> Base16 StrictByteString
headerToHexByteString (Header headerForeignPtr) =
  Base16.assertBase16 $ binaryToHex headerForeignPtr cryptoSecretStreamXChaCha20Poly1305HeaderBytes

-- | Build a 'Header' from a base16-encoded 'StrictByteString'
--
-- @since 0.0.1.0
headerFromHexByteString :: Base16 StrictByteString -> Either Text Header
headerFromHexByteString hexHeader = unsafeDupablePerformIO $
  case Base16.decodeBase16Untyped (Base16.extractBase16 hexHeader) of
    Right bytestring ->
      if BS.length bytestring == fromIntegral cryptoSecretStreamXChaCha20Poly1305HeaderBytes
        then BSU.unsafeUseAsCStringLen bytestring $ \(outsideHeaderPtr, _) -> do
          let headerLength = fromIntegral cryptoSecretStreamXChaCha20Poly1305HeaderBytes
          headerForeignPtr <- Foreign.mallocForeignPtrBytes (fromIntegral cryptoSecretStreamXChaCha20Poly1305HeaderBytes)
          Foreign.withForeignPtr headerForeignPtr $ \headerPtr -> do
            Foreign.copyBytes headerPtr (Foreign.castPtr outsideHeaderPtr) headerLength
            pure $ Right $ Header headerForeignPtr
        else pure $ Left $ Text.pack ("Secret Key is not of size " <> show cryptoSecretStreamXChaCha20Poly1305HeaderBytes)
    Left msg -> pure $ Left msg

-- | Convert a 'Header' to a hexadecimal-encoded 'Text'.
--
-- @since 0.0.1.0
headerToHexText :: Header -> Base16 Text
headerToHexText = Base16.encodeBase16 . Base16.extractBase16 . headerToHexByteString

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

-- | Additional data (AD). Also known as \"additional authenticated data\"
-- (AAD).
--
-- This refers to non-confidential data which is authenticated along with the
-- message, but not encrypted (i.e. its integrity is protected, but it is not
-- made confidential).
--
-- A typical use case for additional data is to authenticate protocol-specific
-- metadata about a message, such as its length and encoding.
newtype AdditionalData = AdditionalData StrictByteString
  deriving stock (Eq, Show)
  deriving (Display) via (ShowInstance AdditionalData)

-- | Convert an 'AdditionalData' value to hexadecimal-encoded 'Text'.
additionalDataToHexText :: AdditionalData -> Base16 Text
additionalDataToHexText = Base16.encodeBase16 . additionalDataToBinary

-- | Convert an 'AdditionalData' value to a hexadecimal-encoded
-- 'StrictByteString'.
additionalDataToHexByteString :: AdditionalData -> Base16 StrictByteString
additionalDataToHexByteString = Base16.encodeBase16' . additionalDataToBinary

-- | Convert an 'AdditionalData' value to a raw binary 'StrictByteString'.
additionalDataToBinary :: AdditionalData -> StrictByteString
additionalDataToBinary (AdditionalData bs) = bs

-- | Error decoding 'AdditionalData' from hexadecimal-encoded bytes.
newtype AdditionalDataHexDecodingError = AdditionalDataHexDecodingError Text
  deriving stock (Eq, Show)

-- | Construct an 'AdditionalData' value from a hexadecimal-encoded
-- 'StrictByteString' that you have obtained on your own, usually from the
-- network or disk.
additionalDataFromHexByteString
  :: Base16 StrictByteString
  -> Either AdditionalDataHexDecodingError AdditionalData
additionalDataFromHexByteString hexBs =
  case Base16.decodeBase16Untyped (Base16.extractBase16 hexBs) of
    Left err -> Left (AdditionalDataHexDecodingError err)
    Right bs -> Right (AdditionalData bs)

-- | An encrypted message. It is guaranteed to be of size:
--  @original_message_length + 'cryptoSecretStreamXChaCha20Poly1305ABytes'@
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
  (Ciphertext ciphertextLength1 h1) == (Ciphertext ciphertextLength2 h2) =
    let
      textLength = ciphertextLength1 == ciphertextLength2
      content =
        foreignPtrEq
          h1
          h2
          (fromIntegral ciphertextLength1 + cryptoSecretStreamXChaCha20Poly1305ABytes)
     in
      textLength && content

-- | @since 0.0.1.0
instance Ord Ciphertext where
  compare (Ciphertext ciphertextLength1 c1) (Ciphertext ciphertextLength2 c2) =
    let
      textLength = compare ciphertextLength1 ciphertextLength2
      content =
        foreignPtrOrd
          c1
          c2
          (fromIntegral ciphertextLength1 + cryptoSecretStreamXChaCha20Poly1305ABytes)
     in
      textLength <> content

-- | @since 0.0.1.0
instance Display Ciphertext where
  displayBuilder = Builder.fromText . Base16.extractBase16 . ciphertextToHexText

-- | @since 0.0.1.0
instance Show Ciphertext where
  show = BSI.unpackChars . Base16.extractBase16 . ciphertextToHexByteString

-- | Create a 'Ciphertext' from a binary 'StrictByteString' that you have obtained on your own,
-- usually from the network or disk. It must be a valid ciphertext built from the concatenation
-- of the encrypted message and the authentication tag.
--
-- The input ciphertext must at least of length 'cryptoSecretStreamXChaCha20Poly1305ABytes'
--
-- @since 0.0.1.0
ciphertextFromHexByteString :: Base16 StrictByteString -> Either Text Ciphertext
ciphertextFromHexByteString hexCiphertext = unsafeDupablePerformIO $
  case Base16.decodeBase16Untyped (Base16.extractBase16 hexCiphertext) of
    Right bytestring ->
      if BS.length bytestring >= fromIntegral cryptoSecretStreamXChaCha20Poly1305ABytes
        then BSU.unsafeUseAsCStringLen bytestring $ \(outsideCiphertextPtr, outsideCiphertextLength) -> do
          ciphertextFPtr <- BSI.mallocByteString @CChar outsideCiphertextLength -- The foreign pointer that will receive the ciphertext data.
          Foreign.withForeignPtr ciphertextFPtr $ \ciphertextPtr ->
            -- We copy bytes from 'outsideCiphertextPtr' to 'ciphertextPtr.
            Foreign.copyArray ciphertextPtr outsideCiphertextPtr outsideCiphertextLength
          pure $
            Right $
              Ciphertext
                (fromIntegral @Int @CULLong outsideCiphertextLength - fromIntegral @CSize @CULLong cryptoSecretStreamXChaCha20Poly1305ABytes)
                (Foreign.castForeignPtr @CChar @CUChar ciphertextFPtr)
        else pure $ Left $ Text.pack "Ciphertext is too short"
    Left msg -> pure $ Left msg

-- | Convert a 'Ciphertext' to a hexadecimal-encoded 'Text'.
--
-- ⚠️  Be prudent as to where you store it!
--
-- @since 0.0.1.0
ciphertextToHexText :: Ciphertext -> Base16 Text
ciphertextToHexText = Base16.encodeBase16 . ciphertextToBinary

-- | Convert a 'Ciphertext' to a hexadecimal-encoded 'StrictByteString' in constant time.
--
-- ⚠️  Be prudent as to where you store it!
--
-- @since 0.0.1.0
ciphertextToHexByteString :: Ciphertext -> Base16 StrictByteString
ciphertextToHexByteString (Ciphertext ciphertextLength fPtr) =
  Base16.assertBase16 $ binaryToHex fPtr (cryptoSecretStreamXChaCha20Poly1305ABytes + fromIntegral ciphertextLength)

-- | Convert a 'Ciphertext' to a binary 'StrictByteString' in constant time.
--
-- ⚠️  Be prudent as to where you store it!
--
-- @since 0.0.1.0
ciphertextToBinary :: Ciphertext -> StrictByteString
ciphertextToBinary (Ciphertext ciphertextLength fPtr) =
  BSI.fromForeignPtr0
    (Foreign.castForeignPtr fPtr)
    (fromIntegral ciphertextLength + fromIntegral cryptoSecretStreamXChaCha20Poly1305ABytes)

-- | @since 0.0.1.0
data StreamEncryptionException = StreamEncryptionException
  deriving stock (Eq, Ord, Show)
  deriving anyclass (Exception)

-- | @since 0.0.1.0
data StreamInitEncryptionException = StreamInitEncryptionException
  deriving stock (Eq, Ord, Show)
  deriving anyclass (Exception)

-- | @since 0.0.1.0
data StreamDecryptionException = StreamDecryptionException
  deriving stock (Eq, Ord, Show)
  deriving anyclass (Exception)
