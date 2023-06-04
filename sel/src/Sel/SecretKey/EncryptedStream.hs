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
-- Module: Sel.SecretKey.EncryptedStream
-- Description: Encrypted Streams
-- Copyright: (C) Hécate Moonlight 2022
-- License: BSD-3-Clause
-- Maintainer: The Haskell Cryptography Group
-- Portability: GHC only
module Sel.SecretKey.EncryptedStream
  ( -- ** Secret Key
    SecretKey
  , newSecretKey

    -- ** CipherText
  , CipherText
  , cipherTextFromByteString
  , cipherTextToBinary
  , cipherTextToHexByteString
  , cipherTextToHexText

    -- ** Stream Header
  , Header
  , headerFromByteString

    -- ** Stream Tags
  , StreamTag (..)
  , streamTagToConstant
  , tagConstantToStreamTag

    -- ** Error type
  , EncryptedStreamError (..)

    -- ** Stream Operations
  , Multipart (..)
  , encryptStream
  -- , decryptStream

    -- *** Encryption
  , initPushStream
  , pushToStream

    -- *** Decryption
  , StreamResult (..)
  , initPullStream
  , pullFromStream

    -- *** Key regeneration
  , rekey
  ) where

import Control.Monad.IO.Class (MonadIO, liftIO)
import Data.ByteString (StrictByteString)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Base16 as Base16
import qualified Data.ByteString.Internal as BS
import qualified Data.ByteString.Unsafe as BS
import Data.Kind (Type)
import Data.Text.Display (Display (..), OpaqueInstance (..), ShowInstance (..))
import Foreign (ForeignPtr, Ptr, Word8)
import qualified Foreign
import Foreign.C (CChar, CSize, CUChar, CULLong)
import qualified GHC.ForeignPtr as Foreign
import GHC.IO.Handle.Text (memcpy)
import System.IO.Unsafe (unsafeDupablePerformIO)

import Data.Text (Text)
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
  , cryptoSecretStreamXChaCha20Poly1305Rekey
  , cryptoSecretStreamXChaCha20Poly1305StateBytes
  , cryptoSecretStreamXChaCha20Poly1305TagFinal
  , cryptoSecretStreamXChaCha20Poly1305TagMessage
  , cryptoSecretStreamXChaCha20Poly1305TagPush
  , cryptoSecretStreamXChaCha20Poly1305TagRekey
  )
import Sel.Internal

-- | The 'SecretKey' is used to encrypt the stream.
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
newSecretKey = do
  fPtr <- Foreign.mallocForeignPtrBytes (fromIntegral cryptoSecretStreamXChaCha20Poly1305KeyBytes)
  Foreign.withForeignPtr fPtr $ \ptr ->
    cryptoSecretStreamXChaCha20Poly1305KeyGen ptr
  pure $ SecretKey fPtr

-- == CipherText ==

-- | A 'CipherText' holds an encrypted message and its own length.
--
-- @since 0.0.1.0
data CipherText
  = CipherText
      !(ForeignPtr CUChar)
      -- ^ Content of the ciphertext
      !CSize
      -- ^ Length of the ciphertext

-- | Convert a binary 'StrictByteString' from the outside (filesystem, network) to a 'CipherText'.
--
-- If the message is not strictly longer than the size of the authentication tag,
-- the function will fail.
--
-- @since 0.0.1.0
cipherTextFromByteString :: StrictByteString -> Maybe CipherText
cipherTextFromByteString bytestring =
  if BS.length bytestring > fromIntegral cryptoSecretStreamXChaCha20Poly1305ABytes
    then unsafeDupablePerformIO $ do
      cipherForeignPtr <- Foreign.mallocPlainForeignPtrBytes (BS.length bytestring)
      Foreign.withForeignPtr cipherForeignPtr $ \cipherPtr ->
        BS.unsafeUseAsCStringLen bytestring $ \(cString, cStringLen) -> do
          memcpy (Foreign.castPtr cipherPtr) cString (fromIntegral cStringLen)
          pure $
            Just $
              CipherText
                cipherForeignPtr
                (fromIntegral @Int @CSize cStringLen)
    else Nothing

-- | Convert a 'CipherText' to a binary 'StrictByteString'.
--
-- @since 0.0.1.0
cipherTextToBinary :: CipherText -> StrictByteString
cipherTextToBinary (CipherText fPtr size) =
  BS.fromForeignPtr0
    (Foreign.castForeignPtr fPtr)
    (fromIntegral size)

-- | Convert a 'CipherText' to a hexadecimal-encoded 'StrictByteString'.
--
-- @since 0.0.1.0
cipherTextToHexByteString :: CipherText -> StrictByteString
cipherTextToHexByteString = Base16.encodeBase16' . cipherTextToBinary

-- | Convert a 'CipherText' to a hexadecimal-encoded 'Text'.
--
-- @since 0.0.1.0
cipherTextToHexText :: CipherText -> Text
cipherTextToHexText = Base16.encodeBase16 . cipherTextToBinary

-- |
--
-- @since 0.0.1.0
instance Eq CipherText where
  (CipherText c1 size1) == (CipherText c2 size2) =
    (size1 == size2) && unsafeDupablePerformIO (foreignPtrEq c1 c2 size1)

-- |
--
-- @since 0.0.1.0
instance Ord CipherText where
  compare (CipherText _c1 size1) (CipherText _c2 size2) = compare size1 size2

-- TODO: Is this even possible?
--
-- @since 0.0.1.0
-- instance Storable CipherText where
--   sizeOf :: CipherText -> Int
--   sizeOf (CipherText c size) = fromIntegral size + cryptoSecretStreamXChaCha20Poly1305ABytes
--
--   --  Aligned on the size of 'cryptoHashSHA512Bytes'
--   alignment :: CipherText -> Int
--   alignment _ = 32
--
--   poke :: Ptr CipherText -> CipherText -> IO ()
--   poke ptr (CipherText c size) =
--     Foreign.withForeignPtr c $ \cipherPtr ->
--       Foreign.copyArray (Foreign.castPtr ptr) cipherPtr (fromIntegral cryptoHashSHA512Bytes + cryptoSecretStreamXChaCha20Poly1305ABytes)
--
--   peek :: Ptr CipherText -> IO CipherText
--   peek ptr = do
--     hashfPtr <- Foreign.mallocForeignPtrBytes (fromIntegral cryptoHashSHA512Bytes + cryptoSecretStreamXChaCha20Poly1305ABytes)
--     Foreign.withForeignPtr hashfPtr $ \hashPtr ->
--       Foreign.copyArray hashPtr (Foreign.castPtr ptr) (fromIntegral cryptoHashSHA512Bytes)
--     pure $ CipherText hashfPtr

-- == Header ==

-- | The 'Header' is a piece of data that starts an encrypted stream.
-- It must be sent or stored before the sequence of encrypted messages, as it is required to decrypt the stream.
--
-- The header content doesn't have to be secret and decryption with a different header will fail.
--
-- @since 0.0.1.0
newtype Header = Header (ForeignPtr CUChar)

-- |
--
-- @since 0.0.1.0
instance Eq Header where
  (Header h1) == (Header h2) =
    unsafeDupablePerformIO $
      foreignPtrEq h1 h2 cryptoSecretStreamXChaCha20Poly1305HeaderBytes

-- |
--
-- @since 0.0.1.0
instance Ord Header where
  compare (Header h1) (Header h2) =
    unsafeDupablePerformIO $
      foreignPtrOrd h1 h2 cryptoSecretStreamXChaCha20Poly1305HeaderBytes

-- | Convert a 'StrictByteString' from the outside (filesystem, network) to a fixed-size 'Header'
--
-- If the bytestring is not of the appropriate length, the function will fail.
--
-- @since 0.0.1.0
headerFromByteString :: StrictByteString -> Maybe Header
headerFromByteString bytestring =
  let (foreignPtr, bsLength) = BS.toForeignPtr0 bytestring
   in if bsLength == fromIntegral @CSize @Int cryptoSecretStreamXChaCha20Poly1305HeaderBytes
        then Just $ Header (Foreign.castForeignPtr @Word8 @CUChar foreignPtr)
        else Nothing

-- == Stream Tags ==

-- | Tags accompany each message.
-- A typical encrypted stream simply attaches 'Message' as a tag to all messages, except the last one which is tagged as 'Final'.
--
-- @since 0.0.1.0
data StreamTag
  = -- | Most common tag, add no information about the nature of the message
    Message
  | -- | Indicates that the message marks the end of a set of messages, but not the end of the stream
    Push
  | -- | "forget" the secret key used to encrypt this message and the previous ones, and derive a new secret key.
    Rekey
  | -- | Marks the end of the stream, and erases the secret key used to encrypt the previous sequence.
    Final
  deriving stock
    ( Eq
      -- ^ @since 0.0.1.0
    , Show
      -- ^ @since 0.0.1.0
    , Ord
      -- ^ @since 0.0.1.0
    , Enum
      -- ^ @since 0.0.1.0
    , Bounded
      -- ^ @since 0.0.1.0
    )
  deriving
    ( Display
      -- ^ @since 0.0.1.0
    )
    via (ShowInstance StreamTag)

-- == Multipart ==

-- | The cryptographic state necessary for streaming operations.
--
-- @since 0.0.1.0
newtype Multipart s = Multipart (Ptr CryptoSecretStreamXChaCha20Poly1305State)

type role Multipart nominal

-- | This record holds the result of a decryption on a stream message
--
-- @since 0.0.1.0
data StreamResult = StreamResult
  { streamMessage :: StrictByteString
  , mStreamTag :: Maybe StreamTag
  , mAdditionalData :: Maybe StrictByteString
  }
  deriving stock
    ( Eq
      -- ^ @since 0.0.1.0
    , Show
      -- ^ @since 0.0.1.0
    , Ord
      -- ^ @since 0.0.1.0
    )
  deriving
    ( Display
      -- ^ @since 0.0.1.0
    )
    via (ShowInstance StreamResult)

-- | Possible errors that can happen during the encryption and decryption process
--
-- @since 0.0.1.0
data EncryptedStreamError
  = InvalidHeader
  | InvalidCipherText
  | InputStreamInitError
  | InputStreamPushError
  deriving stock
    ( Eq
      -- ^ @since 0.0.1.0
    , Show
      -- ^ @since 0.0.1.0
    , Ord
      -- ^ @since 0.0.1.0
    )
  deriving
    ( Display
      -- ^ @since 0.0.1.0
    )
    via (ShowInstance EncryptedStreamError)

-- == Encryption ==

-- | Initialise a stream to which you will push encrypted message.
-- This function returns the 'Header' and the 'SecretKey' that are needed for the peer to
-- decrypt the stream.
--
-- @since 0.0.1.0
initPushStream
  :: Multipart s
  -- ^ Cryptographic state
  -> IO (Either EncryptedStreamError (Header, SecretKey))
initPushStream (Multipart statePtr) = do
  headerForeignPtr <- liftIO $ Foreign.mallocForeignPtrBytes (fromIntegral cryptoSecretStreamXChaCha20Poly1305HeaderBytes)
  (SecretKey secretKeyForeignPtr) <- newSecretKey
  Foreign.withForeignPtr headerForeignPtr $ \headerPtr ->
    Foreign.withForeignPtr secretKeyForeignPtr $ \keyPtr -> do
      result <-
        cryptoSecretStreamXChaCha20Poly1305InitPush
          statePtr
          headerPtr
          keyPtr
      case result of
        0 -> pure $ Right (Header headerForeignPtr, SecretKey secretKeyForeignPtr)
        _ -> pure $ Left InputStreamInitError

-- |
--
-- @since 0.0.1.0
pushToStream
  :: Multipart s
  -- ^ The cryptographic state
  -> StrictByteString
  -- ^ The message to encrypt
  -> Maybe StrictByteString
  -- ^ Additional, optional data that can be included.
  -> StreamTag
  -- ^ Tag that accompanies the resulting 'CipherText'.
  -> IO (Either EncryptedStreamError CipherText)
pushToStream (Multipart statePtr) message mData tag =
  case mData of
    Just additionalData -> do
      let additionalDataLength = BS.length additionalData
      Foreign.allocaBytes additionalDataLength $ \additionalDataPtr ->
        doPushToStream additionalDataPtr (fromIntegral additionalDataLength)
    Nothing -> doPushToStream Foreign.nullPtr 0
  where
    doPushToStream :: Ptr CUChar -> CULLong -> IO (Either EncryptedStreamError CipherText)
    doPushToStream additionalDataPointer additionalDataLength =
      BS.unsafeUseAsCStringLen message $ \(cString, cStringLen) -> do
        let cipherTextLength =
              fromIntegral cryptoSecretStreamXChaCha20Poly1305ABytes + cStringLen
        cipherTextFPtr <- Foreign.mallocForeignPtrBytes cipherTextLength
        Foreign.allocaBytes cipherTextLength $ \cipherTextBuffer -> do
          result <-
            cryptoSecretStreamXChaCha20Poly1305Push
              statePtr
              cipherTextBuffer
              Foreign.nullPtr
              (Foreign.castPtr @CChar @CUChar cString)
              (fromIntegral @Int @CULLong cStringLen)
              additionalDataPointer
              additionalDataLength
              (streamTagToConstant tag)
          case result of
            0 -> do
              Foreign.withForeignPtr cipherTextFPtr $ \cipherTextHomePtr ->
                memcpy cipherTextBuffer cipherTextHomePtr (fromIntegral cipherTextLength)
              pure $ Right $ CipherText cipherTextFPtr (fromIntegral cipherTextLength)
            _ -> pure $ Left InputStreamPushError

-- | Provide a cryptographic context 'Multipart' to encrypt a stream.
--
-- @since 0.0.1.0
encryptStream
  :: forall (m :: Type -> Type)
   . MonadIO m
  => (forall (s :: Type). Multipart s -> IO [CipherText])
  -- ^ Continuation in which the stream gets encrypted
  -> m (Header, SecretKey, [CipherText])
encryptStream action = do
  (SecretKey secretKeyFPtr) <- liftIO newSecretKey
  headerFPtr <- liftIO $ Foreign.mallocForeignPtrBytes (fromIntegral cryptoSecretStreamXChaCha20Poly1305HeaderBytes)
  liftIO $ Foreign.withForeignPtr headerFPtr $ \headerPtr ->
    liftIO $ Foreign.withForeignPtr secretKeyFPtr $ \keyPtr -> do
      Foreign.allocaBytes (fromIntegral cryptoSecretStreamXChaCha20Poly1305StateBytes) $ \statePtr -> do
        cryptoSecretStreamXChaCha20Poly1305InitPush statePtr headerPtr keyPtr
        result <- action $ Multipart statePtr
        pure (Header headerFPtr, SecretKey secretKeyFPtr, result)

-- == Decryption ==

-- | Initialise a stream from which you will retrieve encrypted messages.
--
-- You need the 'Header' and 'SecretKey' used by your peer to intialise the stream in order to
-- sucecessfully decrypt the incoming messages.
--
-- @since 0.0.1.0
initPullStream
  :: Multipart s
  -- ^ Cryptographic state.
  -> Header
  -- ^ Header received from the peer, used to ensure the ciphertexts will be valid.
  -> SecretKey
  -- ^ Secret key from the peer, used to decrypt the ciphertexts.
  -> IO (Either EncryptedStreamError ())
  -- ^ Returns 'True' on success, 'False' if the header is invalid
initPullStream (Multipart statePtr) (Header headerForeignPtr) (SecretKey secretKeyForeignPtr) =
  Foreign.withForeignPtr headerForeignPtr $ \headerPtr ->
    Foreign.withForeignPtr secretKeyForeignPtr $ \keyPtr -> do
      result <-
        cryptoSecretStreamXChaCha20Poly1305InitPull
          statePtr
          headerPtr
          keyPtr
      case result of
        0 -> pure $ Right ()
        _ -> pure $ Left InvalidHeader

-- | Decrypt a stream chunk.
-- Applications will typically call this function in a loop,
-- until a message with the 'Final' tag is found.
--
-- If the tag cannot be decoded from the payload, then it is not returned in the `StreamResult`.
--
-- @since 0.0.1.0
pullFromStream
  :: Multipart s
  -> CipherText
  -> IO (Either EncryptedStreamError StreamResult)
pullFromStream (Multipart state) (CipherText cipherTextForeignPtr cipherTextLength) = do
  decryptedMessageForeignPtr <- Foreign.mallocForeignPtrBytes (fromIntegral @CSize @Int (cipherTextLength - cryptoSecretStreamXChaCha20Poly1305ABytes))
  Foreign.allocaArray 8 $ \tagPtr ->
    Foreign.withForeignPtr decryptedMessageForeignPtr $ \decryptedMessagePtr ->
      Foreign.withForeignPtr cipherTextForeignPtr $ \cipherTextPtr -> do
        resultInt <-
          cryptoSecretStreamXChaCha20Poly1305Pull
            state
            decryptedMessagePtr
            Foreign.nullPtr
            tagPtr
            cipherTextPtr
            (fromIntegral @CSize @CULLong cipherTextLength)
            Foreign.nullPtr
            0
        case resultInt of
          0 -> do
            let decryptedMessage = BS.fromForeignPtr (Foreign.castForeignPtr decryptedMessageForeignPtr) 0 (fromIntegral @CSize @Int (cipherTextLength - cryptoSecretStreamXChaCha20Poly1305ABytes))
            tagConstant :: CUChar <- Foreign.peekByteOff tagPtr 0
            case tagConstantToStreamTag tagConstant of
              Just tag -> pure $ Right $ StreamResult decryptedMessage (Just tag) Nothing
              Nothing -> pure $ Right $ StreamResult decryptedMessage Nothing Nothing
          _ -> pure $ Left InvalidCipherText

-- decryptStream
--   :: forall (m :: Type -> Type)
--    . MonadIO m
--   => (Header, SecretKey)
--   -> (forall (s :: Type). Multipart s -> IO [Either EncryptedStreamError StreamResult])
--   -> m [Maybe StreamResult]
-- decryptStream (header, secretKey) action = do
--   liftIO $ Foreign.allocaBytes (fromIntegral cryptoSecretStreamXChaCha20Poly1305StateBytes) $ \statePtr -> do
--     result <-
--       initPullStream
--         (Multipart statePtr)
--         header
--         secretKey
--     if isRight result
--     then action (Multipart statePtr)
--       else pure [Nothing]

-- | Trigger a key re-generation. You want to do this when your peer sends a message with the 'Rekey' tag on it.
--
-- @since 0.0.1.0
rekey
  :: Multipart s
  -> IO ()
rekey (Multipart state) =
  cryptoSecretStreamXChaCha20Poly1305Rekey state

-- | Convert a 'StreamTag' to its numerical equivalent.
--
-- @since 0.0.1.0
streamTagToConstant :: StreamTag -> CUChar
streamTagToConstant = \case
  Message -> cryptoSecretStreamXChaCha20Poly1305TagMessage
  Push -> cryptoSecretStreamXChaCha20Poly1305TagPush
  Rekey -> cryptoSecretStreamXChaCha20Poly1305TagRekey
  Final -> cryptoSecretStreamXChaCha20Poly1305TagFinal

-- | Convert a number to its equivalent 'StreamTag' or fail
-- if it does not match.
--
-- @since 0.0.1.0
tagConstantToStreamTag :: CUChar -> Maybe StreamTag
tagConstantToStreamTag constant
  | constant == cryptoSecretStreamXChaCha20Poly1305TagMessage = Just Message
  | constant == cryptoSecretStreamXChaCha20Poly1305TagPush = Just Push
  | constant == cryptoSecretStreamXChaCha20Poly1305TagRekey = Just Rekey
  | constant == cryptoSecretStreamXChaCha20Poly1305TagFinal = Just Final
  | otherwise = Nothing
