-- |
--
-- Module: Sel.PublicKey.Signature
-- Description: Public-key signatures with the Ed25519 algorithm
-- Copyright: (C) Hécate Moonlight 2022, Jack Henahan 2024
-- License: BSD-3-Clause
-- Maintainer: The Haskell Cryptography Group
-- Portability: GHC only
module Sel.PublicKey.Signature
  ( -- * Public-key Signatures
    -- $introduction

    -- ** Public keys
    -- $publicKeys
    PublicKey
  , decodePublicKeyHexByteString
  , encodePublicKeyHexByteString

    -- ** Secret keys
    -- $secretKeys
  , SecretKey
  , decodeSecretKeyHexByteString
  , encodeSecretKeyHexByteString
  , publicKey

    -- *** ⚠️ Handle with care
  , UnsafeSecretKey (..)
  , unsafeSecretKeyHexByteString

    -- ** Key Pair generation
  , KeyPair (..)
  , public
  , secret
  , keyPair

    -- *** Deprecated functions
  , generateKeyPair

    -- ** Message Signing
  , SignedMessage
  , signWith
  , signMessage

    -- *** Inspecting signed messages
  , verifiedMessage
  , SignatureVerification (..)
  , signature
  , unverifiedMessage

    -- *** Detached signatures
  , signedMessage

    -- *** Deprecated functions
  , openMessage
  , getSignature
  , unsafeGetMessage
  , mkSignature

    -- ** Exceptions
  , PublicKeyExtractionException (..)
  )
where

import Data.ByteString (StrictByteString)
import Sel.Internal.Scoped (use)
import Sel.PublicKey.Internal.Signature
import System.IO.Unsafe (unsafeDupablePerformIO)

-- $introduction
--
-- Append a signature to any number of messages using a
-- t'SecretKey'. Distribute a t'PublicKey' so third-parties can verify
-- that the messages were signed with a particular t'SecretKey'.
--
-- * The t'SecretKey' must stay private.
--
-- * The t'PublicKey' is not a proof of identity, only control. Ensure
-- that t'PublicKey's are trusted before verifying signatures.

-- $publicKeys
--
-- Public keys are intended to be shared with any party or process
-- which may need to verify that a given message was signed by a
-- particular secret key.
--
-- === Human-readable output
--
-- * @'Data.Text.Display.display' :: t'PublicKey' -> 'Data.Text.Text'@, the hexadecimal encoding of the t'PublicKey' in a 'Data.Text.Text'
-- * @'show' :: t'PublicKey' -> 'String'@, the hexadecimal encoding of the t'PublicKey' in a 'String'

-- $secretKeys
--
-- Secret keys are intended to be private and never shared without
-- extreme care. Leaking a secret key allows anyone to impersonate the
-- creator of that key and sign messages with their identity.
--
-- If a secret key is compromised, all messages signed by that key
-- should be considered compromised.
--
-- Secret keys are compared for equality using the constant-time
-- 'LibSodium.Bindings.Comparison.sodiumMemcmp' to avoid timing attacks.
--
-- __NB:__ Prefer being explicit with t'UnsafeSecretKey' to signal your
-- intent to transmit sensitive key material.
--
-- === ⚠️ Serialization
--
-- * @'encodeSecretKeyHexByteString' :: t'UnsafeSecretKey' -> 'StrictBytestring'@
-- * @'unsafeSecretKeyHexByteString' :: t'SecretKey' -> 'StrictByteString'@
--
-- === ⚠️ Human-readable output
--
-- * @'Text.Display.display' :: t'UnsafeSecretKey' -> 'Data.Text.Text'@, the hexadecimal encoding of the wrapped t'SecretKey' in a 'Data.Text.Text'
-- * @'show' :: t'UnsafeSecretKey' -> 'String'@, the hexadecimal encoding of the wrapped t'SecretKey' in a 'String'

-- | Convert a t'SecretKey' to a hexadecimal-encoded 'StrictByteString'.
--
-- ⚠️ Serializing secret keys is a security risk. Be careful how you
-- use the output of this function.
--
-- @since 0.0.3.0
unsafeSecretKeyHexByteString :: SecretKey -> StrictByteString
unsafeSecretKeyHexByteString = encodeSecretKeyHexByteString . UnsafeSecretKey

-- | Sign a message with a t'SecretKey'.
--
-- === Example
--
-- Given @messages :: 'Traversable' t => t 'StrictByteString'@ and
-- @key :: t'SecretKey'@, we can sign each message with our key.
--
-- @
--   traverse (signWith key) messages -- :: Traversable t => IO (t SignedMessage)
--   -- or, equivalently
--   for messages (signWith key)
-- @
--
-- @since 0.0.3.0
signWith :: SecretKey -> StrictByteString -> IO SignedMessage
signWith secretKey message = use $ sign secretKey message

-- | Sign a message with a t'SecretKey'.
--
-- === Example
--
-- Given @keys :: 'Traversable' t => t t'SecretKey'@ and @message ::
-- 'StrictByteString'@, we can sign our message with each key.
--
-- @
--   traverse (signMessage message) keys -- :: Traversable t => IO (t 'SignedMessage')
--   -- or, equivalently
--   for keys (signMessage message)
-- @
--
-- @since 0.0.1.0
signMessage :: StrictByteString -> SecretKey -> IO SignedMessage
signMessage = flip signWith

-- | Attempt to extract the message from a t'SignedMessage', verifying
-- that the message was signed with the t'SecretKey' corresponding to
-- the given t'PublicKey'.
--
-- @since 0.0.3.0
verifiedMessage :: SignedMessage -> PublicKey -> SignatureVerification StrictByteString
verifiedMessage message key = unsafeDupablePerformIO . use $ open message key

-- | Get the signature part of a t'SignedMessage'.
--
-- @since 0.0.3.0
signature :: SignedMessage -> StrictByteString
signature = unsafeDupablePerformIO . use . extractSignature

-- | Get the message part of a t'SignedMessage' __without verifying the signature__.
--
-- @since 0.0.3.0
unverifiedMessage :: SignedMessage -> StrictByteString
unverifiedMessage = unsafeDupablePerformIO . use . extractUnverifiedMessage

-- | Construct a signed message from a message and a detached signature.
--
-- @since 0.0.3.0
signedMessage :: StrictByteString -> StrictByteString -> SignedMessage
signedMessage messageBytes signatureBytes =
  unsafeDupablePerformIO . use $
    buildSignedMessage messageBytes signatureBytes

{- Deprecated API -}

{- KeyPair -}
{-# DEPRECATED generateKeyPair "Prefer 'keyPair'" #-}

-- | Generate a pair of public and secret key.
--
-- The length parameters used are 'LibSodium.Bindings.CryptoSign.cryptoSignPublicKeyBytes'
-- and 'LibSodium.Bindings.CryptoSign.cryptoSignSecretKeyBytes'.
--
-- @since 0.0.1.0
generateKeyPair :: IO (PublicKey, SecretKey)
generateKeyPair = (,) <$> public <*> secret <$> keyPair

{- SignedMessage -}
{-# DEPRECATED openMessage "Prefer 'verifiedMessage'" #-}
{-# DEPRECATED getSignature "Prefer 'signature'" #-}
{-# DEPRECATED unsafeGetMessage "Prefer 'unverifiedMessage'" #-}
{-# DEPRECATED mkSignature "Prefer 'signedMessage'" #-}

-- | Attempt to extract a the message from a t'SignedMessage',
-- verifying that the message was signed with the t'SecretKey'
-- corresponding to the given t'PublicKey', yielding `Nothing` if the
-- key is not applicable.
--
-- @since 0.0.1.0
openMessage :: SignedMessage -> PublicKey -> Maybe StrictByteString
openMessage message key =
  case verifiedMessage message key of
    Valid msg -> Just msg
    Invalid -> Nothing

-- | Get the signature part of a t'SignedMessage'.
--
-- @since 0.0.1.0
getSignature :: SignedMessage -> StrictByteString
getSignature = signature

-- | Get the message part of a t'SignedMessage' __without verifying the signature__.
--
-- @since 0.0.1.0
unsafeGetMessage :: SignedMessage -> StrictByteString
unsafeGetMessage = unverifiedMessage

-- | Construct a signed message from a message and a detached signature.
--
-- @since 0.0.1.0
mkSignature :: StrictByteString -> StrictByteString -> SignedMessage
mkSignature = signedMessage
