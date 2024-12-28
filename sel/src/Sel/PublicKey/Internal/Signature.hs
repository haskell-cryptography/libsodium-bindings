{-# LANGUAGE DataKinds #-}
{-# LANGUAGE DeriveAnyClass #-}
{-# LANGUAGE DeriveTraversable #-}
{-# LANGUAGE DerivingVia #-}
{-# LANGUAGE ImportQualifiedPost #-}
{-# LANGUAGE NamedFieldPuns #-}
{-# LANGUAGE OverloadedRecordDot #-}
{-# LANGUAGE TypeApplications #-}
{-# LANGUAGE ViewPatterns #-}

module Sel.PublicKey.Internal.Signature
  ( -- ** Public Keys
    PublicKey
  , decodePublicKeyHexByteString
  , encodePublicKeyHexByteString

    -- ** Secret Keys
  , SecretKey
  , decodeSecretKeyHexByteString
  , unsafeEncodeSecretKeyHexByteString
  , publicKey

    -- ** Key Pairs
  , KeyPair (..)
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
import Data.Base16.Types qualified as Base16
import Data.ByteString (StrictByteString)
import Data.ByteString.Base16 qualified as Base16
import Data.ByteString.Internal qualified as ByteString
import Data.ByteString.Unsafe qualified as ByteString
import Data.Coerce (coerce)
import Data.Text.Display (Display, OpaqueInstance (..), ShowInstance (..))
import Data.Traversable (for)
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
import Sel.Internal
  ( foreignPtrEq
  , foreignPtrEqConstantTime
  , foreignPtrOrd
  , foreignPtrOrdConstantTime
  , unsafeCopyToSodiumPointer
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
import Sel.KeyMaterialDecodeError
import System.IO.Unsafe (unsafeDupablePerformIO)

-- | A public key of size 'cryptoSignPublicKeyBytes', suitable for
-- publication to third parties for message verification.
--
-- @since 0.0.1.0
newtype PublicKey = PublicKey (ForeignPtr CUChar)
  deriving
    ( Display
      -- ^ @since 0.0.3.0
      -- Hexadecimal-encoded bytes.
    )
    via (ShowInstance PublicKey)

-- | By lexicographical comparison of pointer contents.
--
-- @since 0.0.1.0
instance Eq PublicKey where
  a == b =
    foreignPtrEq (coerce a) (coerce b) cryptoSignPublicKeyBytes

-- | By lexicographical comparison of pointer contents.
--
-- @since 0.0.1.0
instance Ord PublicKey where
  a `compare` b =
    foreignPtrOrd (coerce a) (coerce b) cryptoSignPublicKeyBytes

-- | Hexadecimal-encoded bytes.
--
-- @since 0.0.3.0
instance Show PublicKey where
  show = ByteString.unpackChars . encodePublicKeyHexByteString

-- | Decode a hexadecimal-encoded 'StrictByteString' to a t'PublicKey'.
--
-- @since 0.0.3.0
decodePublicKeyHexByteString :: StrictByteString -> Either KeyMaterialDecodeError PublicKey
decodePublicKeyHexByteString bytes = PublicKey <$> copyHexKey cryptoSignPublicKeyBytes bytes

-- | Encode a t'PublicKey' to a hexadecimal encoded 'StrictByteString'.
--
-- @since 0.0.3.0
encodePublicKeyHexByteString :: PublicKey -> StrictByteString
encodePublicKeyHexByteString (PublicKey publicKeyPtr) =
  Base16.extractBase16 . Base16.encodeBase16' $
    ByteString.fromForeignPtr0
      (Foreign.castForeignPtr publicKeyPtr)
      (fromIntegral cryptoSignPublicKeyBytes)

-- | A secret key of size 'cryptoSignSecretKeyBytes'. Keep this private.
--
-- @since 0.0.1.0
newtype SecretKey = SecretKey (ForeignPtr CUChar)
  deriving
    ( Display
      -- ^ @since 0.0.3.0
      -- > display secretKey == "[REDACTED]"
    )
    via (OpaqueInstance "[REDACTED]" SecretKey)

-- | By constant-time comparison of pointer contents.
--
-- @since 0.0.3.0
instance Eq SecretKey where
  a == b =
    foreignPtrEqConstantTime (coerce a) (coerce b) cryptoSignSecretKeyBytes

-- | By constant-time lexicographical comparison of pointer contents.
--
-- @since 0.0.3.0
instance Ord SecretKey where
  a `compare` b =
    foreignPtrOrdConstantTime (coerce a) (coerce b) cryptoSignSecretKeyBytes

-- | > show secretKey == "[REDACTED]"
--
-- @since 0.0.3.0
instance Show SecretKey where
  show _ = "[REDACTED]"

-- | Decode a hexadecimal-encoded 'StrictByteString' to a t'SecretKey'.
--
-- @since 0.0.3.0
decodeSecretKeyHexByteString :: StrictByteString -> Either KeyMaterialDecodeError SecretKey
decodeSecretKeyHexByteString bytes = SecretKey <$> copyHexKey cryptoSignSecretKeyBytes bytes

-- | Encode a t'SecretKey' to a hexadecimal encoded 'StrictByteString'.
--
-- ⚠️ This is a security risk! Be careful how you use the output of
-- this function!
--
-- @since 0.0.3.0
unsafeEncodeSecretKeyHexByteString :: SecretKey -> StrictByteString
unsafeEncodeSecretKeyHexByteString (SecretKey secretKeyPtr) =
  Base16.extractBase16 . Base16.encodeBase16' $
    ByteString.fromForeignPtr0
      (Foreign.castForeignPtr secretKeyPtr)
      (fromIntegral cryptoSignSecretKeyBytes)

-- | Produce the t'PublicKey' from a t'SecretKey'.
--
-- This function may throw a t'PublicKeyExtractionException' if the
-- operation fails.
publicKey :: SecretKey -> PublicKey
publicKey (SecretKey secretKeyPtr) = unsafeDupablePerformIO $ do
  publicKeyPtr <- Foreign.mallocForeignPtrBytes (fromIntegral cryptoSignPublicKeyBytes)
  res <-
    useM $
      cryptoSignED25519SkToPk
        <$> foreignPtr publicKeyPtr
        <*> foreignPtr secretKeyPtr
  unless (res == 0) $ throw PublicKeyExtractionException
  pure $ PublicKey publicKeyPtr

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
-- @since 0.0.3.0
instance Ord KeyPair where
  compare kp1 kp2 =
    compare kp1.public kp2.public
      <> compare kp1.secret kp2.secret

-- | Generate a fresh t'KeyPair'.
--
-- @since 0.0.3.0
keyPair :: IO KeyPair
keyPair = do
  publicKeyPtr <- Foreign.mallocForeignPtrBytes (fromIntegral cryptoSignPublicKeyBytes)
  secretKeyPtr <- Foreign.mallocForeignPtrBytes (fromIntegral cryptoSignSecretKeyBytes)
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
  show msg = unsafeDupablePerformIO $ use $ do
    message <- extractUnverifiedMessage msg
    sig <- extractSignature msg
    let showMessage = ByteString.unpackChars message
        showSig = ByteString.unpackChars . Base16.extractBase16 . Base16.encodeBase16' $ sig
    pure $
      mconcat
        [ "SignedMessage { message = \""
        , showMessage
        , "\", signature = \""
        , showSig
        , "\" }"
        ]

-- | By message length, then lexicographical comparison of message and
-- signature pointer contents.
--
-- @since 0.0.1.0
instance Eq SignedMessage where
  (SignedMessage len1 msg1 sig1) == (SignedMessage len2 msg2 sig2) =
    let
      messageLength = len1 == len2
      messageEq = foreignPtrEq msg1 msg2 len1
      signatureEq = foreignPtrEq sig1 sig2 cryptoSignBytes
     in
      messageLength && messageEq && signatureEq

-- | By message length, then lexicographical comparison of message and
-- signature pointer contents.
--
-- @since 0.0.1.0
instance Ord SignedMessage where
  compare (SignedMessage len1 msg1 sig1) (SignedMessage len2 msg2 sig2) =
    let
      messageLength = compare len1 len2
      messageOrd = foreignPtrOrd msg1 msg2 len1
      signatureOrd = foreignPtrOrd sig1 sig2 cryptoSignBytes
     in
      messageLength <> messageOrd <> signatureOrd

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

-- | Copy a hexadecimal-encoded bytestring to some key pointer.
--
-- Input is checked for encoding and length.
--
-- @since 0.0.3.0
copyHexKey :: CSize -> StrictByteString -> Either KeyMaterialDecodeError (ForeignPtr CUChar)
copyHexKey size bytes =
  unsafeDupablePerformIO $
    for (validKeyMaterial size bytes) (unsafeCopyToSodiumPointer size)
