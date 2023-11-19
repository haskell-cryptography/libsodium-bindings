{-# LANGUAGE CApiFFI #-}

-- |
-- Module: LibSodium.Bindings.SealedBoxes
-- Description: Direct bindings to the sealed boxes API of Libsodium
-- License: BSD-3-Clause
-- Maintainer: The Haskell Cryptography Group
-- Stability: Stable
-- Portability: GHC only
module LibSodium.Bindings.SealedBoxes
  ( -- * Introduction
    -- $introduction

    -- * Functions
    cryptoBoxSeal
  , cryptoBoxSealOpen
  , cryptoBoxKeyPair
  , cryptoBoxSeedKeyPair

    -- * Constants
  , cryptoBoxSealbytes
  ) where

import Foreign (Ptr)
import Foreign.C (CInt (CInt), CSize (CSize), CUChar, CULLong (CULLong))
import LibSodium.Bindings.CryptoBox (cryptoBoxKeyPair, cryptoBoxSeedKeyPair)

-- $introduction
-- Sealed boxes are designed to anonymously send messages to a recipient
-- given their public key.
--
-- Only the recipient can decrypt these messages using their secret key.
-- While the recipient can verify the integrity of the message, they cannot
-- verify the identity of the sender.
--
-- A message is encrypted using an ephemeral key pair, with the secret key being
-- erased right after the encryption process.
--
-- Without knowing the secret key used for a given message, the sender cannot decrypt
-- the message later. Furthermore, without additional data, a message cannot be
-- correlated with the identity of its sender.

-- | @cryptoBoxSeal@ creates a new key pair for each message and attaches the public
--   key to the ciphertext. The secret key is overwritten and is not accessible
--   after this function returns.
--
-- /See:/ [crypto_box_seal()](https://doc.libsodium.org/public-key_cryptography/sealed_boxes#usage)
--
-- @since 0.0.1.0
foreign import capi "sodium.h crypto_box_seal"
  cryptoBoxSeal
    :: Ptr CUChar
    -- ^ Buffer that will hold the encrypted message of size
    --   (size of original message + 'cryptoBoxSealbytes') bytes
    -> Ptr CUChar
    -- ^ Buffer that holds the plaintext message
    -> CULLong
    -- ^ Length of the plaintext message
    -> Ptr CUChar
    -- ^ Buffer that holds public key of size
    --  'LibSodium.Bindings.CryptoBox.cryptoBoxPublicKeyBytes' bytes.
    -> IO CInt
    -- ^ Returns 0 on success and -1 on error.

-- | 'cryptoBoxSealOpen' doesn't require passing the public key of
--   the sender as the ciphertext already includes this information.
--
--   Key pairs are compatible with operations from 'LibSodium.Bindings.CryptoBox'
--   module and can be created using 'LibSodium.Bindings.CryptoBox.cryptoBoxKeyPair'
--   or 'LibSodium.Bindings.CryptoBox.cryptoBoxSeedKeyPair'.
--
-- /See:/ [crypto_box_seal_open()](https://doc.libsodium.org/public-key_cryptography/sealed_boxes#usage)
--
-- @since 0.0.1.0
foreign import capi "sodium.h crypto_box_seal_open"
  cryptoBoxSealOpen
    :: Ptr CUChar
    -- ^ Buffer that will hold the plaintext message of size
    --   (size of original message - 'cryptoBoxSealbytes') bytes
    -> Ptr CUChar
    -- ^ Buffer that holds the encrypted message.
    -> CULLong
    -- ^ Length of the encrypted message
    -> Ptr CUChar
    -- ^ Buffer that holds public key of size
    --  'LibSodium.Bindings.CryptoBox.cryptoBoxPublicKeyBytes' bytes.
    -> Ptr CUChar
    -- ^ Buffer that holds secret key of size
    --  'LibSodium.Bindings.CryptoBox.cryptoBoxSecretKeyBytes' bytes.
    -> IO CInt
    -- ^ Returns 0 on success and -1 on error.

-- | Size diff in bytes between encrypted and plaintext messages, i.e.
--   @cryptoBoxSealbytes = length encryptedMsg - length plaintextMsg@
--
-- @since 0.0.1.0
foreign import capi "sodium.h value crypto_box_SEALBYTES"
  cryptoBoxSealbytes :: CSize
