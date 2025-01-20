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
  , publicKey

    -- *** ⚠️ Handle with care
  , unsafeEncodeSecretKeyHexByteString

    -- ** Key Pair generation
  , generateKeyPair

    -- ** Message Signing
  , SignedMessage
  , signMessage

    -- *** Inspecting signed messages
  , openMessage
  , getSignature
  , unsafeGetMessage

    -- *** Detached signatures
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
-- Secret keys are compared for equality using
-- 'LibSodium.Bindings.Comparison.sodiumMemcmp' and lexicographically
-- using 'LibSodium.Bindings.Comparison.sodiumCompare', both
-- constant-time comparisons, to guard against timing attacks.
--
-- === ⚠️ Serialization
--
-- * @'unsafeEncodeSecretKeyHexByteString' :: t'SecretKey' -> 'StrictBytestring'@

-- | Generate a pair of public and secret key.
--
-- The length parameters used are 'LibSodium.Bindings.CryptoSign.cryptoSignPublicKeyBytes'
-- and 'LibSodium.Bindings.CryptoSign.cryptoSignSecretKeyBytes'.
--
-- @since 0.0.1.0
generateKeyPair :: IO (PublicKey, SecretKey)
generateKeyPair = (,) <$> public <*> secret <$> keyPair

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
signMessage message secretKey = use $ sign secretKey message

-- | Attempt to extract the message from a t'SignedMessage', verifying
-- that the message was signed with the t'SecretKey' corresponding to
-- the given t'PublicKey'.
--
-- @since 0.0.1.0
openMessage :: SignedMessage -> PublicKey -> Maybe StrictByteString
openMessage message key =
  case unsafeDupablePerformIO . use $ open message key of
    Valid msg -> Just msg
    Invalid -> Nothing

-- | Get the signature part of a t'SignedMessage'.
--
-- @since 0.0.1.0
getSignature :: SignedMessage -> StrictByteString
getSignature = unsafeDupablePerformIO . use . extractSignature

-- | Get the message part of a t'SignedMessage' __without verifying the signature__.
--
-- @since 0.0.1.0
unsafeGetMessage :: SignedMessage -> StrictByteString
unsafeGetMessage = unsafeDupablePerformIO . use . extractUnverifiedMessage

-- | Construct a signed message from a message and a detached signature.
--
-- @since 0.0.1.0
mkSignature :: StrictByteString -> StrictByteString -> SignedMessage
mkSignature messageBytes signatureBytes =
  unsafeDupablePerformIO . use $
    buildSignedMessage messageBytes signatureBytes
