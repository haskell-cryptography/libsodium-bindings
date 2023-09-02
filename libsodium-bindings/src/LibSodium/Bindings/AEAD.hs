{-# LANGUAGE CApiFFI #-}

-- |
--
-- Module: LibSodium.Bindings.AEAD
-- Description: Bindings to AEAD constructions with XChaCha20-Poly1305-IETF.
-- Copyright: (C) Hécate Moonlight 2023
-- License: BSD-3-Clause
-- Maintainer: The Haskell Cryptography Group
-- Stability: Stable
-- Portability: GHC only
module LibSodium.Bindings.AEAD
  ( -- * Introduction
    -- $introduction

    -- * Operations
    cryptoAEADXChaCha20Poly1305IETFEncrypt
  , cryptoAEADXChaCha20Poly1305IETFDecrypt
  , cryptoAEADXChaCha20Poly1305IETFEncryptDetached
  , cryptoAEADXChaCha20Poly1305IETFDecryptDetached

    -- * Constants
  , cryptoAEADXChaCha20Poly1305IETFKeyBytes
  , cryptoAEADXChaCha20Polt1305IETFPubBytes
  , cryptoAEADXChaCha20Poly1305IETFABytes
  )
where

import Foreign.C.Types (CInt (CInt), CSize (CSize), CUChar, CULLong (CULLong))
import Foreign.Ptr (Ptr)

-- $introduction
--
-- With @XChaCha20-Poly1305-IETF@, you can encrypt a message witha key and a nonce to keept it
-- confidential, as well as compute an authentication tag to make sure that the message
-- has not been tampered with.
--
-- A typical use case for additional data is to authenticate protocol-specific metadata
-- about the message, such as its length and encoding.
--
-- For a deeper dive into the limitations of the implementation, please refer to the manual:
-- https://doc.libsodium.org/secret-key_cryptography/aead#limitations

-- | This function encrypts a message, and then appends the authentication tag
-- to the encrypted message.
--
-- /See also:/ [crypto_aead_xchacha20poly1305_ietf_encrypt()](https://doc.libsodium.org/secret-key_cryptography/aead/chacha20-poly1305/xchacha20-poly1305_construction#combined-mode)
--
-- @since 0.0.1.0
foreign import capi "sodium.h crypto_aead_xchacha20poly1305_ietf_encrypt"
  cryptoAEADXChaCha20Poly1305IETFEncrypt
    :: Ptr CUChar
    -- ^ Output buffer. Contains the encrypted message, authentication tag, and non-confidential additional data.
    -> Ptr CULLong
    -- ^ Size of computed output. Should be message length plus 'cryptoAEADXChaCha20Poly1305IETFABytes'.
    -- If set to 'Foreign.Ptr.nullPtr', then no bytes will be written to this buffer.
    -> Ptr CUChar
    -- ^ Message to be encrypted.
    -> CULLong
    -- ^ Message length.
    -> Ptr CUChar
    -- ^ Non-confidential additional data. Can be null with additional data length of 0 if
    -- no additional data is required.
    -> CULLong
    -- ^ Additional data length.
    -> Ptr CUChar
    -- ^ @nsec@, a parameter not used in this function. Should always be 'Foreign.Ptr.nullPtr'.
    -> Ptr CUChar
    -- ^ Public nonce of size 'cryptoAEADXChaCha20Polt1305IETFPubBytes'.
    -- Should never be reused with the same key. Nonces can be generated using 'LibSodium.Bindings.Random.randombytesBuf'.
    -> Ptr CUChar
    -- ^ Secret key of size 'cryptoAEADXChaCha20Poly1305IETFKeyBytes'.
    -> IO CInt
    -- ^ Returns -1 on failure, 0 on success.

-- | This function verifies that an encrypted ciphertext includes a valid tag.
--
-- /See also:/ [crypto_aead_xchacha20poly1305_ietf_decrypt()](https://doc.libsodium.org/secret-key_cryptography/aead/chacha20-poly1305/xchacha20-poly1305_construction#combined-mode)
--
-- @since 0.0.1.0
foreign import capi "sodium.h crypto_aead_xchacha20poly1305_ietf_decrypt"
  cryptoAEADXChaCha20Poly1305IETFDecrypt
    :: Ptr CUChar
    -- ^ Output buffer. At most the cipher text length minus 'cryptoAEADXChaCha20Poly1305IETFABytes' will be put into this.
    -> Ptr CULLong
    -- ^ Size of computed output. Should be message length plus 'cryptoAEADXChaCha20Poly1305IETFABytes'.
    -- If set to 'Foreign.Ptr.nullPtr', then no bytes will be written to this buffer.
    -> Ptr CUChar
    -- ^ @nsec@, a parameter not used in this function. Should always be 'Foreign.Ptr.nullPtr'.
    -> Ptr CUChar
    -- ^ Ciphertext to decrypt.
    -> CULLong
    -- ^ Ciphertext length.
    -> Ptr CUChar
    -- ^ Non-confidential additional data. Can be null with additional data length of 0 if
    -- no additional data is required.
    -> CULLong
    -- ^ Additional data length.
    -> Ptr CUChar
    -- ^ Public nonce of size 'cryptoAEADXChaCha20Polt1305IETFPubBytes'.
    -- Should never be reused with the same key. Nonces can be generated using 'LibSodium.Bindings.Random.randombytesBuf'.
    -> Ptr CUChar
    -- ^ Secret key of size 'cryptoAEADXChaCha20Poly1305IETFKeyBytes'.
    -> IO CInt
    -- ^ Returns -1 on failure, 0 on success.

-- | This is the "detached" version of the encryption function.
-- The encrypted message and authentication tag are output to different buffers
-- instead of the tag being appended to the encrypted message.
--
-- /See also:/ [crypto_aead_xchacha20poly1305_ietf_encrypt_detached()](https://doc.libsodium.org/secret-key_cryptography/aead/chacha20-poly1305/xchacha20-poly1305_construction#detached-mode)
--
-- @since 0.0.1.0
foreign import capi "sodium.h crypto_aead_xchacha20poly1305_ietf_encrypt_detached"
  cryptoAEADXChaCha20Poly1305IETFEncryptDetached
    :: Ptr CUChar
    -- ^ Output buffer. Contains the encrypted message with length equal to the message.
    -> Ptr CUChar
    -- ^ The authentication tag. Has length 'cryptoAEADXChaCha20Poly1305IETFABytes'.
    -> Ptr CULLong
    -- ^ Length of the authentication tag buffer.
    -> Ptr CUChar
    -- ^ Message to be encrypted.
    -> CULLong
    -- ^ Length of input message.
    -> Ptr CUChar
    -- ^ Additional, non-confidential data.
    -> CULLong
    -- ^ Length of the additional, non-confidential data.
    -> Ptr CUChar
    -- ^ Not used in this particular construction, should always be 'Foreign.Ptr.nullPtr'.
    -> Ptr CUChar
    -- ^ Public nonce of size 'cryptoAEADXChaCha20Polt1305IETFPubBytes'.
    -- Should never be reused with the same key. Nonces can be generated using 'LibSodium.Bindings.Random.randombytesBuf'.
    -> Ptr CUChar
    -- ^ Secret key of size 'cryptoAEADXChaCha20Poly1305IETFKeyBytes'.
    -> IO CInt
    -- ^ Returns -1 on failure, 0 on success.

-- | This is the "detached" version of the decryption function.
-- Verifies that the authentication tag is valid for the ciphertext, key, nonce,
-- and additional data.
--
-- /See also:/ [crypto_aead_xchacha20poly1305_ietf_decrypt_detached()](https://doc.libsodium.org/secret-key_cryptography/aead/chacha20-poly1305/xchacha20-poly1305_construction#detached-mode)
--
-- @since 0.0.1.0
foreign import capi "sodium.h crypto_aead_xchacha20poly1305_ietf_decrypt_detached"
  cryptoAEADXChaCha20Poly1305IETFDecryptDetached
    :: Ptr CUChar
    -- ^ If the tag is valid, the ciphertext is decrypted and put into this buffer.
    -> Ptr CUChar
    -- ^ Not used in this particular construction, should always be 'Foreign.Ptr.nullPtr'.
    -> Ptr CUChar
    -- ^ Ciphertext to be decrypted.
    -> CULLong
    -- ^ Length of the ciphertext.
    -> Ptr CUChar
    -- ^ The authentication tag. Has length 'cryptoAEADXChaCha20Poly1305IETFABytes'.
    -> Ptr CUChar
    -- ^ Additional, non-confidential data.
    -> CULLong
    -- ^ Length of the additional, non-confidential data.
    -> Ptr CUChar
    -- ^ Public nonce of size 'cryptoAEADXChaCha20Polt1305IETFPubBytes'.
    -- Should never be reused with the same key. Nonces can be generated using 'LibSodium.Bindings.Random.randombytesBuf'.
    -> Ptr CUChar
    -- ^ Secret key of size 'cryptoAEADXChaCha20Poly1305IETFKeyBytes'.
    -> IO CInt
    -- ^ Returns 0 on success, -1 if tag is not valid.

-- == Constants.

-- | Recommended length of a key for this construction.
--
-- /See also:/ [crypto_aead_xchacha20poly1305_ietf_KEYBYTES](https://doc.libsodium.org/secret-key_cryptography/aead/chacha20-poly1305/xchacha20-poly1305_construction#constants)
--
-- @since 0.0.1.0
foreign import capi "sodium.h value crypto_aead_xchacha20poly1305_ietf_KEYBYTES"
  cryptoAEADXChaCha20Poly1305IETFKeyBytes :: CSize

-- | Recommended length of a nonce for this construction.
--
-- /See also:/ [crypto_aead_xchacha20poly1305_ietf_NPUBBYTES](https://doc.libsodium.org/secret-key_cryptography/aead/chacha20-poly1305/xchacha20-poly1305_construction#constants)
--
-- @since 0.0.1.0
foreign import capi "sodium.h value crypto_aead_xchacha20poly1305_ietf_NPUBBYTES"
  cryptoAEADXChaCha20Polt1305IETFPubBytes :: CSize

-- | Recommended length for the authentication tag.
--
-- /See also:/ [crypto_aead_xchacha20poly1305_ietf_ABYTES](https://doc.libsodium.org/secret-key_cryptography/aead/chacha20-poly1305/xchacha20-poly1305_construction#constants)
--
-- @since 0.0.1.0
foreign import capi "sodium.h value crypto_aead_xchacha20poly1305_ietf_ABYTES"
  cryptoAEADXChaCha20Poly1305IETFABytes :: CSize
