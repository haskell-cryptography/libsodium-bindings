{-# LANGUAGE ConstraintKinds #-}
{-# LANGUAGE DataKinds #-}
{-# LANGUAGE DeriveAnyClass #-}
{-# LANGUAGE DeriveTraversable #-}
{-# LANGUAGE DerivingVia #-}
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE ImportQualifiedPost #-}
{-# LANGUAGE NamedFieldPuns #-}
{-# LANGUAGE OverloadedRecordDot #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE StandaloneDeriving #-}
{-# LANGUAGE TypeApplications #-}
{-# LANGUAGE ViewPatterns #-}
{-# LANGUAGE NoFieldSelectors #-}

module Sel.PublicKey.Internal.Signature
  ( -- ** Public Keys
    PublicKey
  , decodePublicKeyHexByteString
  , encodePublicKeyHexByteString

    -- ** Secret Keys
  , SecretKey
  , decodeSecretKeyHexByteString
  , encodeSecretKeyHexByteString
  , UnsafeSecretKey (..)
  , publicKey

    -- ** Key Pairs
  , KeyPair (..)
  , public
  , secret
  , keyPair

    -- ** Signed Messages
  , SignedMessage
  , sign
  , open
  , SignatureVerification (..)
  , extractUnverifiedMessage
  , extractSignature
  , buildSignedMessage

    -- ** Exceptions
  , PublicKeyExtractionException (..)
  )
where

import Control.Exception (Exception, throw)
import Control.Monad (unless)
import Control.Monad.Trans.Class (lift)
import Data.ByteString (StrictByteString)
import Data.ByteString.Unsafe qualified as ByteString
import Data.Ord (comparing)
import Data.Text.Display (Display, OpaqueInstance (..), ShowInstance (..))
import Foreign (ForeignPtr)
import Foreign qualified
import Foreign.C (CChar, CSize, CUChar, CULLong)
import LibSodium.Bindings.CryptoSign
  ( cryptoSignBytes
  , cryptoSignDetached
  , cryptoSignED25519SkToPk
  , cryptoSignKeyPair
  , cryptoSignPublicKeyBytes
  , cryptoSignSecretKeyBytes
  , cryptoSignVerifyDetached
  )
import Sel.ByteString.Codec
  ( decodeHexByteString
  , encodeHexByteString
  , showHexEncoding
  )
import Sel.ByteString.Codec.KeyMaterialDecodeError
import Sel.ByteString.Codec.KeyPointer
import Sel.Internal.Instances
  ( foreignPtrEq
  , foreignPtrOrd
  , foreignPtrShow
  )
import Sel.Internal.Scoped
import Sel.Internal.Scoped.Foreign
  ( copyArray
  , foreignPtr
  , mallocBytes
  , mallocForeignPtrBytes
  , unsafeCString
  , unsafeCStringLen
  )
import System.IO.Unsafe (unsafeDupablePerformIO)

-- | A public key of size 'cryptoSignPublicKeyBytes', suitable for
-- publication to third parties for message verification.
newtype PublicKey = PublicKey (ForeignPtr CUChar)
  deriving
    ( Eq
      -- ^ @since 0.0.1.0
      -- By lexicographical comparison of pointer contents.
    , Ord
      -- ^ @since 0.0.1.0
      -- By lexicographical comparison of pointer contents.
    )
    via (KeyPointer PublicKey ShortCircuiting)
  deriving
    ( Display
      -- ^ @since 0.0.3.0
      -- Hexadecimal-encoded bytes.
    )
    via (ShowInstance PublicKey)

-- | Decode a hexadecimal-encoded 'StrictByteString' to a 'PublicKey'
-- using the default copying decoder.
--
-- @since 0.0.3.0
decodePublicKeyHexByteString :: StrictByteString -> Either KeyMaterialDecodeError PublicKey
decodePublicKeyHexByteString = decodeHexByteString @PublicKey

-- | Encode an 'PublicKey' to a hexadecimal encoded 'StrictByteString'
-- using the default copying encoder.
--
-- @since 0.0.3.0
encodePublicKeyHexByteString :: PublicKey -> StrictByteString
encodePublicKeyHexByteString = encodeHexByteString @PublicKey

-- | A public key uses a pointer of size 'cryptoSignPublicKeyBytes'.
--
-- @since 0.0.3.0
instance KeyPointerSize PublicKey where
  keyPointerSize = cryptoSignPublicKeyBytes

-- | Hexadecimal-encoded bytes.
--
-- @since 0.0.3.0
instance Show PublicKey where
  show = showHexEncoding

-- | A secret key of size 'cryptoSignSecretKeyBytes'. Keep this private.
newtype SecretKey = SecretKey (ForeignPtr CUChar)
  deriving
    ( Eq
      -- ^ @since 0.0.1.0
      -- By constant-time pointer content comparison.
    )
    via (KeyPointer SecretKey ConstantTime)
  deriving
    ( Display
      -- ^ @since 0.0.3.0
      -- > display secretKey == "[REDACTED]"
    )
    via (OpaqueInstance "[REDACTED]" SecretKey)

-- | Decode a hexadecimal-encoded 'StrictByteString' to a 'SecretKey'
-- using the default copying decoder.
--
-- @since 0.0.3.0
decodeSecretKeyHexByteString :: StrictByteString -> Either KeyMaterialDecodeError SecretKey
decodeSecretKeyHexByteString = decodeHexByteString @SecretKey

-- | Encode an 'UnsafeSecretKey' to a hexadecimal encoded
-- 'StrictByteString' using the default copying encoder.
--
-- @since 0.0.3.0
encodeSecretKeyHexByteString :: UnsafeSecretKey -> StrictByteString
encodeSecretKeyHexByteString = encodeHexByteString @UnsafeSecretKey

-- | Produce the t'PublicKey' from a t'SecretKey'.
--
-- This function may throw a t'PublicKeyExtractionException' if the operation fails.
publicKey :: SecretKey -> PublicKey
publicKey (SecretKey secretKeyPtr) = unsafeDupablePerformIO $ do
  publicKeyPtr <- keyPointer @PublicKey
  res <-
    useM $
      cryptoSignED25519SkToPk
        <$> foreignPtr publicKeyPtr
        <*> foreignPtr secretKeyPtr
  unless (res == 0) $ throw PublicKeyExtractionException
  pure $ PublicKey publicKeyPtr

-- | A secret key uses a pointer of size 'cryptoSignSecretKeyBytes'.
--
-- @since 0.0.3.0
instance KeyPointerSize SecretKey where
  keyPointerSize = cryptoSignSecretKeyBytes

-- | > show secretKey == "[REDACTED]"
--
-- @since 0.0.3.0
instance Show SecretKey where
  show _ = "[REDACTED]"

-- | Signal your intent to encode secret key material for transmission
-- by wrapping a t'SecretKey' in t'UnsafeSecretKey'.
--
-- @since 0.0.3.0
newtype UnsafeSecretKey = UnsafeSecretKey SecretKey
  deriving newtype
    ( Eq
      -- ^ @since 0.0.3.0
      -- Follows the t'SecretKey' instance.
    , KeyPointerSize
      -- ^ @since 0.0.3.0
      -- Follows the t'SecretKey' instance.
    )
  deriving
    ( Display
      -- ^ @since 0.0.3.0
      -- Hexadecimal-encoded bytes.
    )
    via (ShowInstance UnsafeSecretKey)

-- | Hexadecimal-encoded bytes.
--
-- @since 0.0.3.0
instance Show UnsafeSecretKey where
  show = showHexEncoding

-- | By lexicographical comparison of pointer contents.
--
-- ⚠️ Vulnerable to timing attacks!
--
-- @since 0.0.3.0
deriving via (KeyPointer SecretKey ShortCircuiting) instance Ord UnsafeSecretKey

-- | A signing key pair, comprising a t'PublicKey' and a t'SecretKey'.
--
-- @since 0.0.3.0
data KeyPair = KeyPair {public :: PublicKey, secret :: SecretKey}
  deriving stock
    ( Show
      -- ^ @since 0.0.3.0
      -- Follows the instances for t'PublicKey' and t'SecretKey', respectively.
      --
      -- In particular, the secret key will be shown as @[REDACTED]@.
    , Eq
      -- ^ @since 0.0.3.0
      -- Follows the instances for t'PublicKey' and t'SecretKey', respectively.
    )
  deriving
    ( Display
      -- ^ @since 0.0.3.0
      -- Follows the instances for t'PublicKey' and t'SecretKey', respectively.
      --
      -- In particular, the secret key will be displayed as @[REDACTED]@.
    )
    via (ShowInstance KeyPair)

-- | By lexicographical comparison of key pointer contents.
--
-- ⚠️ Vulnerable to timing attacks!
--
-- @since 0.0.3.0
instance Ord KeyPair where
  compare kp1 kp2 =
    compare kp1.public kp2.public
      <> comparing UnsafeSecretKey kp1.secret kp2.secret

-- | The t'PublicKey' in a t'KeyPair'.
--
-- @since 0.0.3.0
public :: KeyPair -> PublicKey
public = (.public)

-- | The t'SecretKey' in a t'KeyPair'.
--
-- @since 0.0.3.0
secret :: KeyPair -> SecretKey
secret = (.secret)

-- | Generate a fresh t'KeyPair'.
--
-- @since 0.0.3.0
keyPair :: IO KeyPair
keyPair = do
  publicKeyPtr <- keyPointer @PublicKey
  secretKeyPtr <- keyPointer @SecretKey
  useM_ $ cryptoSignKeyPair <$> foreignPtr publicKeyPtr <*> foreignPtr secretKeyPtr
  pure $ KeyPair (PublicKey publicKeyPtr) (SecretKey secretKeyPtr)

-- | A message of known length together with its signature of length
-- 'cryptoSignBytes'.
--
-- @since 0.0.1.0
data SignedMessage = SignedMessage
  { messageLength :: CSize
  -- ^ Original message length
  , messageForeignPtr :: ForeignPtr CUChar
  , signatureForeignPtr :: ForeignPtr CUChar
  }

-- | > show message = "SignedMessage { message = \"<contents>\", signature = \"<signature>\" }"
--
-- @since 0.0.3.0
instance Show SignedMessage where
  show (SignedMessage len msg sig) = unsafeDupablePerformIO $ do
    messageShow <- foreignPtrShow msg len
    signatureShow <- foreignPtrShow sig cryptoSignBytes
    pure $
      mconcat
        [ "SignedMessage { message = \""
        , messageShow
        , "\", signature = \""
        , signatureShow
        , "\" }"
        ]

-- | By message length, then lexicographical comparison of message and
-- signature pointer contents.
--
-- @since 0.0.1.0
instance Eq SignedMessage where
  (SignedMessage len1 msg1 sig1) == (SignedMessage len2 msg2 sig2) =
    unsafeDupablePerformIO $ do
      messageEq <- foreignPtrEq msg1 msg2 len1
      signatureEq <- foreignPtrEq sig1 sig2 cryptoSignBytes
      pure $ (len1 == len2) && messageEq && signatureEq

-- | By message length, then lexicographical comparison of message and
-- signature pointer contents.
--
-- @since 0.0.1.0
instance Ord SignedMessage where
  compare (SignedMessage len1 msg1 sig1) (SignedMessage len2 msg2 sig2) =
    unsafeDupablePerformIO $ do
      messageOrder <- foreignPtrOrd msg1 msg2 len1
      signatureOrder <- foreignPtrOrd sig1 sig2 cryptoSignBytes
      pure $ compare len1 len2 <> messageOrder <> signatureOrder

-- | Sign a message with a t'SecretKey'.
sign :: SecretKey -> StrictByteString -> Scoped IO SignedMessage
sign (SecretKey secretKeyForeignPtr) message = do
  (cstring, messageLength) <- unsafeCStringLen message
  messageForeignPtr <- mallocForeignPtrBytes messageLength
  signatureForeignPtr <- mallocForeignPtrBytes (fromIntegral @CSize @Int cryptoSignBytes)
  reset $ do
    messagePtr <- foreignPtr messageForeignPtr
    copyArray messagePtr (Foreign.castPtr @CChar @CUChar cstring) messageLength
    signaturePtr <- foreignPtr signatureForeignPtr
    secretKeyPtr <- foreignPtr secretKeyForeignPtr
    lift $
      cryptoSignDetached
        signaturePtr
        Foreign.nullPtr
        (Foreign.castPtr @CChar @CUChar cstring)
        (fromIntegral @Int @CULLong messageLength)
        secretKeyPtr
  pure
    SignedMessage
      { messageLength = fromIntegral @Int @CSize messageLength
      , messageForeignPtr
      , signatureForeignPtr
      }

-- | Result of detached signature verification.
--
-- @since 0.0.3.0
data SignatureVerification a
  = -- | The signature was created by the expected t'SecretKey'.
    --
    -- @since 0.0.3.0
    Valid a
  | -- | The signature was not created by the expected t'SecretKey'.
    --
    -- @since 0.0.3.0
    Invalid
  deriving stock
    ( Eq
      -- ^ @since 0.0.3.0
    , Ord
      -- ^ @since 0.0.3.0
    , Show
      -- ^ @since 0.0.3.0
    , Functor
      -- ^ @since 0.0.3.0
    , Foldable
      -- ^ @since 0.0.3.0
    , Traversable
      -- ^ @since 0.0.3.0
    )
  deriving
    ( Display
      -- ^ @since 0.0.3.0
    )
    via (ShowInstance (SignatureVerification a))

-- | Verify that a message was signed by the t'SecretKey' corresponding
-- to the given t'PublicKey'.
--
-- @since 0.0.3.0
verify :: SignedMessage -> PublicKey -> Scoped IO (SignatureVerification SignedMessage)
verify message (PublicKey publicKeyForeignPtr) = do
  result <- reset $ do
    publicKeyPtr <- foreignPtr publicKeyForeignPtr
    signaturePtr <- foreignPtr message.signatureForeignPtr
    messagePtr <- foreignPtr message.messageForeignPtr
    lift $
      cryptoSignVerifyDetached
        signaturePtr
        messagePtr
        (fromIntegral @CSize @CULLong message.messageLength)
        publicKeyPtr
  pure $ if result == 0 then Valid message else Invalid

-- | Attempt to extract the message from a t'SignedMessage', verifying
-- that the message was signed with the t'SecretKey' corresponding to
-- the given t'PublicKey'.
--
-- @since 0.0.3.0
open :: SignedMessage -> PublicKey -> Scoped IO (SignatureVerification StrictByteString)
open message key = traverse extractUnverifiedMessage =<< verify message key

-- | Extract a part of a t'SignedMessage' without verifying the signature.
--
-- @since 0.0.3.0
unverifiedExtract
  :: (SignedMessage -> ForeignPtr CUChar)
  -> CSize
  -> SignedMessage
  -> Scoped IO StrictByteString
unverifiedExtract target fieldLength (target -> field) = do
  fieldPtr <- foreignPtr field
  bsPtr <- mallocBytes (fromIntegral fieldLength)
  lift $ Foreign.copyBytes bsPtr fieldPtr (fromIntegral fieldLength)
  lift $ do
    ByteString.unsafePackMallocCStringLen
      ( Foreign.castPtr @_ @CChar bsPtr
      , fromIntegral fieldLength
      )

-- | Extract the message part of a t'SignedMessage' without verifying the signature.
--
-- @since 0.0.3.0
extractUnverifiedMessage :: SignedMessage -> Scoped IO StrictByteString
extractUnverifiedMessage msg = unverifiedExtract (.messageForeignPtr) msg.messageLength msg

-- | Extract the signature part of a t'SignedMessage' without verifying the signature.
--
-- @since 0.0.3.0
extractSignature :: SignedMessage -> Scoped IO StrictByteString
extractSignature = unverifiedExtract (.signatureForeignPtr) cryptoSignBytes

-- | Construct a t'SignedMessage' from the message contents and a detached signature.
--
-- @since 0.0.3.0
buildSignedMessage :: StrictByteString -> StrictByteString -> Scoped IO SignedMessage
buildSignedMessage message signature = do
  (messageString, messageLength) <- unsafeCStringLen message
  messageForeignPtr <- mallocForeignPtrBytes messageLength
  signatureForeignPtr <- mallocForeignPtrBytes (fromIntegral cryptoSignBytes)
  reset $ do
    signatureString <- unsafeCString signature
    messagePtr <- foreignPtr messageForeignPtr
    signaturePtr <- foreignPtr signatureForeignPtr
    copyArray messagePtr (Foreign.castPtr messageString) messageLength
    copyArray signaturePtr (Foreign.castPtr signatureString) (fromIntegral cryptoSignBytes)
  pure
    SignedMessage
      { messageLength = fromIntegral @Int @CSize messageLength
      , messageForeignPtr
      , signatureForeignPtr
      }

-- | Thrown when we fail to extract a t'PublicKey' from a t'SecretKey'.
--
-- @since 0.0.3.0
data PublicKeyExtractionException = PublicKeyExtractionException
  deriving stock
    ( Eq
      -- ^ @since 0.0.3.0
    , Ord
      -- ^ @since 0.0.3.0
    , Show
      -- ^ @since 0.0.3.0
    )
  deriving anyclass
    ( Exception
      -- ^ @since 0.0.3.0
    )
