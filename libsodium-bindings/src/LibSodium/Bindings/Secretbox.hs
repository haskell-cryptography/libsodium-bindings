{-# LANGUAGE CApiFFI #-}
{-# LANGUAGE Trustworthy #-}

-- |
-- Module: LibSodium.Bindings.Secretbox
-- Description: Direct bindings to the secretbox API of Libsodium
-- License: BSD-3-Clause
-- Maintainer: The Haskell Cryptography Group
-- Stability: Stable
-- Portability: GHC only
module LibSodium.Bindings.Secretbox
  ( -- * Introduction
    -- $introduction

    -- * Secretbox

    -- ** Keygen
    cryptoSecretboxKeygen

    -- ** Easy
  , cryptoSecretboxEasy
  , cryptoSecretboxOpenEasy

    -- ** Detached
  , cryptoSecretboxDetached
  , cryptoSecretboxOpenDetached

    -- ** Constants
  , cryptoSecretboxKeyBytes
  , cryptoSecretboxNonceBytes
  , cryptoSecretboxMACBytes
  , cryptoSecretboxPrimitive
  , cryptoSecretboxMessageBytesMax
  )
where

import Foreign (Ptr)
import Foreign.C (CChar, CInt (CInt), CSize (CSize), CUChar, CULLong (CULLong))

-- $introduction
-- This API allows encrypting a message using a secret key and a nonce.
-- The ciphertext is accompanied by an authentication tag.
--
--
-- It comes in two flavours:
--
--   [easy] Both the ciphertext and authentication tag are stored in the same buffer.
--   [detached] The ciphertext and authentication tag may be stored in separate buffers.
--
--
-- The same key is used for both encryption and decryption, so it must be kept secret.
-- A key can be generated using the 'cryptoSecretboxKeygen' primitive.
--
--
-- Each message must use a unique nonce, which may be generated with the 'LibSodium.Bindings.Random.randombytesBuf' primitive.
-- The nonce does not need to be kept secret but should never be reused with the same secret key.
--
-- For more information see the upstream docs: <https://doc.libsodium.org/secret-key_cryptography/secretbox>

-- | Generate a key that can be used by the primitives of the secretbox API.
--
-- /See also:/ [crypto_secretbox_keygen()](https://doc.libsodium.org/secret-key_cryptography/secretbox#detached-mode)
--
-- @since 0.0.1.0
foreign import capi "sodium.h crypto_secretbox_keygen"
  cryptoSecretboxKeygen
    :: Ptr CUChar
    -- ^ key buffer of length 'cryptoSecretboxKeyBytes'
    -> IO ()

-- | Encrypt a message using a secret key and nonce.
--
-- The message and ciphertext buffers may overlap enabling in-place encryption, but note that the
-- ciphertext will be 'cryptoSecretboxMACBytes' bytes longer than the message.
--
-- /See also:/ [crytpo_secretbox_easy()](https://doc.libsodium.org/secret-key_cryptography/secretbox#combined-mode)
--
-- @since 0.0.1.0
foreign import capi "sodium.h crypto_secretbox_easy"
  cryptoSecretboxEasy
    :: Ptr CUChar
    -- ^ A pointer to the buffer that will hold the ciphertext.
    -- The length of the ciphertext is the length of the message in bytes plus 'cryptoSecretboxMACBytes' bytes.
    -> Ptr CUChar
    -- ^ A pointer to the buffer holding the message to be encrypted.
    -> CULLong
    -- ^ The length of the message in bytes.
    -> Ptr CUChar
    -- ^ A pointer to the nonce of size 'cryptoSecretboxNonceBytes' bytes.
    -> Ptr CUChar
    -- ^ A pointer to the secret key of size 'cryptoSecretboxKeyBytes' bytes.
    -> IO CInt
    -- ^ Returns 0 on success and -1 on error.

-- | Verify and decrypt ciphertext using a secret key and nonce.
--
-- The message and ciphertext buffers may overlap enabling in-place decryption, but note that the
-- message will be 'cryptoSecretboxMACBytes' bytes shorter than the ciphertext.
--
-- /See also:/ [crypto_secretbox_open_easy()](https://doc.libsodium.org/secret-key_cryptography/secretbox#combined-mode)
--
-- @since 0.0.1.0
foreign import capi "sodium.h crypto_secretbox_open_easy"
  cryptoSecretboxOpenEasy
    :: Ptr CUChar
    -- ^ A pointer to the buffer that will hold the decrypted message.
    -- The length of the message is the length of the ciphertext in bytes minus 'cryptoSecretboxMACBytes' bytes.
    -> Ptr CUChar
    -- ^ A pointer to the buffer holding the ciphertext to be verified and decrypted.
    -> CULLong
    -- ^ The length of the ciphertext in bytes.
    -> Ptr CUChar
    -- ^ A pointer to the nonce of size 'cryptoSecretboxNonceBytes' bytes.
    -> Ptr CUChar
    -- ^ A pointer to the secret key of size 'cryptoSecretboxKeyBytes' bytes.
    -> IO CInt
    -- ^ Returns 0 on success and -1 on error.

-- | Encrypt a message using a secret key and nonce.
--
-- /See also:/ [crypto_secretbox_detached()](https://doc.libsodium.org/secret-key_cryptography/secretbox#detached-mode)
--
-- @since 0.0.1.0
foreign import capi "sodium.h crypto_secretbox_detached"
  cryptoSecretboxDetached
    :: Ptr CUChar
    -- ^ A pointer to the buffer that will hold the ciphertext. This will have the same length as the message.
    -> Ptr CUChar
    -- ^ A pointer to the buffer that will hold the authentication tag.
    -- This will be of length 'cryptoSecretboxMACBytes' bytes.
    -> Ptr CUChar
    -- ^ A pointer to the buffer holding the message to be encrypted.
    -> CULLong
    -- ^ The length of the message in bytes.
    -> Ptr CUChar
    -- ^ A pointer to the nonce of size 'cryptoSecretboxNonceBytes' bytes.
    -> Ptr CUChar
    -- ^ A pointer to the secret key of size 'cryptoSecretboxKeyBytes' bytes.
    -> IO CInt
    -- ^ Returns 0 on success and -1 on error.

-- | Verify and decrypt ciphertext using a secret key and nonce
--
-- /See also:/ [crypto_secretbox_open_detached()](https://doc.libsodium.org/secret-key_cryptography/secretbox#detached-mode)
--
-- @since 0.0.1.0
foreign import capi "sodium.h crypto_secretbox_open_detached"
  cryptoSecretboxOpenDetached
    :: Ptr CUChar
    -- ^ A pointer to the buffer that will hold the decrypted message. This will have the same length as the ciphertext.
    -> Ptr CUChar
    -- ^ A pointer to the buffer holding the ciphertext to be decrypted.
    -> Ptr CUChar
    -- ^ A pointer to the buffer holding the authentication tag to be verified.
    -> CULLong
    -- ^ The length of the ciphertext in bytes.
    -> Ptr CUChar
    -- ^ A pointer to the nonce of size 'cryptoSecretboxNonceBytes' bytes.
    -> Ptr CUChar
    -- ^ A pointer to the secret key of size 'cryptoSecretboxKeyBytes' bytes.
    -> IO CInt
    -- ^ Returns 0 on success and -1 on error.

-- | The length of a secretbox key in bytes.
--
-- /See also:/ [crypto_secretbox_KEYBYTES](https://doc.libsodium.org/secret-key_cryptography/secretbox#constants)
--
-- @since 0.0.1.0
foreign import capi "sodium.h value crypto_secretbox_KEYBYTES"
  cryptoSecretboxKeyBytes :: CSize

-- | The length of a secretbox nonce in bytes.
--
-- /See also:/ [crypto_secretbox_NONCEBYTES](https://doc.libsodium.org/secret-key_cryptography/secretbox#constants)
--
-- @since 0.0.1.0
foreign import capi "sodium.h value crypto_secretbox_NONCEBYTES"
  cryptoSecretboxNonceBytes :: CSize

-- | The length of a secretbox authentication tag in bytes.
--
-- /See also:/ [crypto_secretbox_MACBYTES](https://doc.libsodium.org/secret-key_cryptography/secretbox#constants)
--
-- @since 0.0.1.0
foreign import capi "sodium.h value crypto_secretbox_MACBYTES"
  cryptoSecretboxMACBytes :: CSize

-- | The underlying cryptographic algorithm used to implement the secretbox API.
--
-- /See also:/ [crypto_secretbox_PRIMITIVE](https://doc.libsodium.org/secret-key_cryptography/secretbox#algorithm-details)
--
-- @since 0.0.1.0
foreign import capi "sodium.h value crypto_secretbox_PRIMITIVE"
  cryptoSecretboxPrimitive :: Ptr CChar

-- | Maximum length of a message in bytes that can be encrypted using the secretbox API.
--
-- /See also:/ [crypto_secretbox_MESSAGEBYTES_MAX](https://doc.libsodium.org/secret-key_cryptography/secretbox#constants)
--
-- @since 0.0.1.0
foreign import capi "sodium.h value crypto_secretbox_MESSAGEBYTES_MAX"
  cryptoSecretboxMessageBytesMax :: CSize
