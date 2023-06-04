{-# LANGUAGE CApiFFI #-}
{-# LANGUAGE ScopedTypeVariables #-}

-- |
-- Module: LibSodium.Bindings.SecretStream
-- Description: Direct bindings to the stream and file encryption primitives of libsodium
-- Copyright: (C) Hécate Moonlight 2022
-- License: BSD-3-Clause
-- Maintainer: The Haskell Cryptography Group
-- Stability: Stable
-- Portability: GHC only
module LibSodium.Bindings.SecretStream
  ( -- * Introduction
    -- $introduction

    -- * Usage
    -- $usage
    CryptoSecretStreamXChaCha20Poly1305State
  , withCryptoSecretStreamXChaCha20Poly1305State

    -- * Encryption
  , cryptoSecretStreamXChaCha20Poly1305KeyGen
  , cryptoSecretStreamXChaCha20Poly1305InitPush
  , cryptoSecretStreamXChaCha20Poly1305Push

    -- * Decryption
  , cryptoSecretStreamXChaCha20Poly1305InitPull
  , cryptoSecretStreamXChaCha20Poly1305Pull

    -- * Rekeying
  , cryptoSecretStreamXChaCha20Poly1305Rekey

    -- * Constants

    -- ** Key, Header and State size constants
  , cryptoSecretStreamXChaCha20Poly1305KeyBytes
  , cryptoSecretStreamXChaCha20Poly1305HeaderBytes
  , cryptoSecretStreamXChaCha20Poly1305StateBytes
  , cryptoSecretStreamXChaCha20Poly1305ABytes
  , cryptoSecretStreamXChaCha20Poly1305MessageBytesMax

    -- ** Tag constants
  , cryptoSecretStreamXChaCha20Poly1305TagMessage
  , cryptoSecretStreamXChaCha20Poly1305TagPush
  , cryptoSecretStreamXChaCha20Poly1305TagRekey
  , cryptoSecretStreamXChaCha20Poly1305TagFinal
  ) where

import Foreign (Ptr)
import Foreign.C (CInt (CInt), CSize (CSize), CUChar (CUChar), CULLong (CULLong))
import Foreign.Marshal (allocaBytes)

-- $introduction
-- This high-level API encrypts a sequence of messages, or a single message split into an arbitrary number of chunks, using a secret key, with the following properties:
--
-- * Messages cannot be truncated, removed, reordered, duplicated or modified without this being detected by the decryption functions.
-- * The same sequence encrypted twice will produce different ciphertexts.
-- * An authentication tag is added to each encrypted message: stream corruption will be detected early, without having to read the stream until the end.
-- * Each message can include additional data (ex: timestamp, protocol version) in the computation of the authentication tag.
-- * Messages can have different sizes.
-- * There are no practical limits to the total length of the stream, or to the total number of individual messages.
-- * Ratcheting: at any point in the stream, it is possible to "forget" the secret key used to encrypt the previous messages, and switch to a new key.

-- $usage
-- An encrypted stream starts with a short header, whose size is 'cryptoSecretStreamXChaCha20Poly1305HeaderBytes' bytes.
-- That header must be sent/stored before the sequence of encrypted messages, as it is required to decrypt the stream.
-- The header content doesn't have to be secret and decryption with a different header would fail.
--
-- A tag is attached to each message. That tag can be any of:
--
-- * 0, or 'cryptoSecretStreamXChaCha20Poly1305TagMessage': the most common tag, that doesn't add any information about the nature of the message.
--
-- * 'cryptoSecretStreamXChaCha20Poly1305TagFinal': indicates that the message marks the end of the stream, and erases the secret key used to encrypt the previous sequence.
--
-- * 'cryptoSecretStreamXChaCha20Poly1305TagPush': indicates that the message marks the end of a set of messages, but not the end of the stream.
--   For example, a huge JSON string sent as multiple chunks can use this tag to indicate to the application that the string is complete and that it
--   can be decoded. But the stream itself is not closed, and more data may follow.
--
-- * 'cryptoSecretStreamXChaCha20Poly1305TagRekey': "forget" the secret key used to encrypt this message and the previous ones, and derive a new secret key.
--
-- A typical encrypted stream simply attaches 0 as a tag to all messages, except the last one which is tagged as 'cryptoSecretStreamXChaCha20Poly1305TagFinal'.
--
-- Note that tags are encrypted; encrypted streams do not reveal any information about sequence boundaries
-- ('cryptoSecretStreamXChaCha20Poly1305TagPush' and 'cryptoSecretStreamXChaCha20Poly1305TagRekey' tags).
--
-- For each message, additional data can be included in the computation of the authentication tag.
-- With this API, additional data is rarely required, and most applications can just use 'Foreign.Ptr.nullPtr' and a length of 0 instead.

-- | Opaque tag representing the hash state struct @crypto_secretstream_xchacha20poly1305_state@ used by the C API.
--
-- To use a 'CryptoSecretStreamXChaCha20Poly1305State', use 'withCryptoSecretStreamXChaCha20Poly1305State'.
--
-- @since 0.0.1.0
data CryptoSecretStreamXChaCha20Poly1305State

-- | Allocate an opaque 'CryptoSecretStreamXChaCha20Poly1305State' of size 'cryptoSecretStreamXChaCha20Poly1305StateBytes'.
--
-- ⚠️ Do not leak the 'CryptoSecretStreamXChaCha20Poly1305State' outside of the lambda,
-- otherwise you will point at deallocated memory!
--
-- @since 0.0.1.0
withCryptoSecretStreamXChaCha20Poly1305State :: (Ptr CryptoSecretStreamXChaCha20Poly1305State -> IO a) -> IO a
withCryptoSecretStreamXChaCha20Poly1305State action = allocaBytes (fromIntegral cryptoSecretStreamXChaCha20Poly1305StateBytes) action

-- === Encryption ===

-- | Create a random secret key to encrypt a stream, and store it into the parameter
--
-- Note that using this function is not required to obtain a suitable key:
-- the secretstream API can use any secret key whose size is
-- 'cryptoSecretStreamXChaCha20Poly1305KeyBytes' bytes.
--
-- /See:/ [crypto_secretstream_xchacha20poly1305_keygen()](https://doc.libsodium.org/secret-key_cryptography/secretstream#encryption)
--
-- @since 0.0.1.0
foreign import capi "sodium.h crypto_secretstream_xchacha20poly1305_keygen"
  cryptoSecretStreamXChaCha20Poly1305KeyGen
    :: Ptr CUChar
    -- ^ Pointer in which the secret key will be stored
    -> IO ()

-- | Initialise the cryptographic state using the secret key, then stores the stream header into the header buffer
--
-- /See:/ [crypto_secretstream_xchacha20poly1305_init_push()](https://doc.libsodium.org/secret-key_cryptography/secretstream#encryption)
--
-- @since 0.0.1.0
foreign import capi "sodium.h crypto_secretstream_xchacha20poly1305_init_push"
  cryptoSecretStreamXChaCha20Poly1305InitPush
    :: Ptr CryptoSecretStreamXChaCha20Poly1305State
    -- ^ Cryptographic state
    -> Ptr CUChar
    -- ^ Header buffer, must be of size 'cryptoSecretStreamXChaCha20Poly1305HeaderBytes'.
    -> Ptr CUChar
    -- ^ Buffer holding the secret key. Must be of size 'cryptoSecretStreamXChaCha20Poly1305KeyBytes'.
    -> IO CInt
    -- ^ Returns 0 on success, -1 on error.

-- | Encrypt a message using a cryptographic state and a tag.
--
-- Additional data can be optionally provided.
-- The maximum length of an individual message is 'cryptoSecretStreamXChaCha20Poly1305MessageBytesMax' bytes (~ 256 GB).
--
-- /See:/ [crypto_secretstream_xchacha20poly1305_push()](https://doc.libsodium.org/secret-key_cryptography/secretstream#encryption)
--
-- @since 0.0.1.0
foreign import capi "sodium.h crypto_secretstream_xchacha20poly1305_push"
  cryptoSecretStreamXChaCha20Poly1305Push
    :: Ptr CryptoSecretStreamXChaCha20Poly1305State
    -- ^ Cryptographic state
    -> Ptr CUChar
    -- ^ Buffer that receives the cipher text.
    -> Ptr CULLong
    -- ^ If this pointer is not 'Foreign.Ptr.nullPtr', it will store the length of the cipher text.
    -- It is guaranteed to be always @(messageLength + 'cryptoSecretStreamXChaCha20Poly1305ABytes' )@.
    -> Ptr CUChar
    -- ^ Pointer to the message to encrypt
    -> CULLong
    -- ^ Length of the message (@messageLength@).
    -> Ptr CUChar
    -- ^ Additional, optional data that can be included in the computation. Can be 'Foreign.Ptr.nullPtr' if you have nothing to add.
    -> CULLong
    -- ^ Length of the additional, optional data. Can be 0 if you have nothing to add.
    -> CUChar
    -- ^ Tag for the cipher text.
    -> IO CInt
    -- ^ Returns 0 on success, -1 on error.

-- === Decryption ===

-- | Initialise the cryptographic state using the secret key and a header.
-- The secret key will not be required any more for subsequent operations
--
-- @since 0.0.1.0
--
-- /See:/ [crypto_secretstream_xchacha20poly1305_init_pull()](https://doc.libsodium.org/secret-key_cryptography/secretstream#decryption)
foreign import capi "sodium.h crypto_secretstream_xchacha20poly1305_init_pull"
  cryptoSecretStreamXChaCha20Poly1305InitPull
    :: Ptr CryptoSecretStreamXChaCha20Poly1305State
    -- ^ Cryptographic state
    -> Ptr CUChar
    -- ^ Header buffer, must be of size 'cryptoSecretStreamXChaCha20Poly1305HeaderBytes'.
    -> Ptr CUChar
    -- ^ Buffer holding the secret key. Must be of size 'cryptoSecretStreamXChaCha20Poly1305KeyBytes'.
    -> IO CInt
    -- ^ Returns 0 on success, -1 if the header is invalid.

-- | Decrypt a message chunk.
--
-- Applications will typically call this function in a loop, until a message with the
-- 'cryptoSecretStreamXChaCha20Poly1305TagFinal' tag is found.
--
-- /See:/ [crypto_secretstream_xchacha20poly1305_pull()](https://doc.libsodium.org/secret-key_cryptography/secretstream#decryption)
--
-- @since 0.0.1.0
foreign import capi "sodium.h crypto_secretstream_xchacha20poly1305_pull"
  cryptoSecretStreamXChaCha20Poly1305Pull
    :: Ptr CryptoSecretStreamXChaCha20Poly1305State
    -- ^ Cryptographic state.
    -> Ptr CUChar
    -- ^ Buffer that will hold the decrypted message.
    -> Ptr CULLong
    -- ^ If this pointer is not 'Foreign.Ptr.nullPtr', it will store the length of the message.
    -- It is guaranteed to be always @(cipherTextLength - 'cryptoSecretStreamXChaCha20Poly1305ABytes' )@.
    -> Ptr CUChar
    -- ^ If this pointer is not 'Foreign.Ptr.nullPtr', the tag attached to the message is stored in that buffer.
    -> Ptr CUChar
    -- ^ Cipher text to be decrypted.
    -> CULLong
    -- ^ Length in bytes of the cipher text.
    -> Ptr CUChar
    -- ^ Additional, optional data that was bundled with the cipher text will be put there. Can be 'Foreign.Ptr.nullPtr' if you know that nothing was added.
    -> CULLong
    -- ^ Length of the additional, optional data. Can be 0 if you have nothing to add.
    -> IO CInt
    -- ^ Return 0 on success, -1 if the ciphertext appears to be invalid.

-- === Rekeying ===

-- | Rekeying happens automatically and transparently, before the internal counter of the underlying cipher wraps. Therefore, streams can be arbitrary large.
--
-- Optionally, applications for which forward secrecy is critical can attach the 'cryptoSecretStreamXChaCha20Poly1305TagRekey'
-- tag to a message in order to trigger an explicit rekeying.
--
-- The decryption API will automatically update the secret key if this tag is found attached to a message.
-- Explicit rekeying can also be performed without adding a tag, by calling this function.
--
-- This updates the state, but doesn't add any information about the secret key change to the stream.
-- If this function is used to create an encrypted stream, the decryption process must call
-- that function at the exact same stream location.
--
-- /See:/ [crypto_secretstream_xchacha20poly1305_rekey()](https://doc.libsodium.org/secret-key_cryptography/secretstream#rekeying)
--
-- @since 0.0.1.0
foreign import capi "sodium.h crypto_secretstream_xchacha20poly1305_rekey"
  cryptoSecretStreamXChaCha20Poly1305Rekey
    :: Ptr CryptoSecretStreamXChaCha20Poly1305State
    -- ^ Cryptographic state.
    -> IO ()

-- === Constants ===

-- | Size of the secret key
--
-- /See:/ [crypto_secretstream_xchacha20poly1305_KEYBYTES](https://doc.libsodium.org/secret-key_cryptography/secretstream#constants)
--
-- @since 0.0.1.0
foreign import capi "sodium.h value crypto_secretstream_xchacha20poly1305_KEYBYTES"
  cryptoSecretStreamXChaCha20Poly1305KeyBytes :: CSize

-- | Size of the encryption header
--
-- /See:/ [crypto_secretstream_xchacha20poly1305_HEADERBYTES](https://doc.libsodium.org/secret-key_cryptography/secretstream#constants)
--
-- @since 0.0.1.0
foreign import capi "sodium.h value crypto_secretstream_xchacha20poly1305_HEADERBYTES"
  cryptoSecretStreamXChaCha20Poly1305HeaderBytes :: CSize

-- | Size of an opaque 'CryptoSecretStreamXChaCha20Poly1305State'
--
-- /See:/ [crypto_secretstream_xchacha20poly1305_statebytes](https://doc.libsodium.org/secret-key_cryptography/secretstream#constants)
--
-- @since 0.0.1.0
foreign import capi "sodium.h crypto_secretstream_xchacha20poly1305_statebytes"
  cryptoSecretStreamXChaCha20Poly1305StateBytes :: CSize

-- | Size of an authentication tag in bytes
--
-- /See:/ [crypto_secretstream_xchacha20poly1305_ABYTES](https://doc.libsodium.org/secret-key_cryptography/secretstream#constants)
--
-- @since 0.0.1.0
foreign import capi "sodium.h value crypto_secretstream_xchacha20poly1305_ABYTES"
  cryptoSecretStreamXChaCha20Poly1305ABytes :: CSize

-- | Maximum length of an invidual message in bytes (~ 256 GB)
--
-- /See:/ [crypto_secretstream_xchacha20poly1305_MESSAGEBYTES_MAX](https://doc.libsodium.org/secret-key_cryptography/secretstream#constants)
--
-- @since 0.0.1.0
foreign import capi "sodium.h value crypto_secretstream_xchacha20poly1305_MESSAGEBYTES_MAX"
  cryptoSecretStreamXChaCha20Poly1305MessageBytesMax :: CSize

-- | Most common tag, add no information about the nature of the message
--
-- /See:/ [crypto_secretstream_xchacha20poly1305_TAG_MESSAGE](https://doc.libsodium.org/secret-key_cryptography/secretstream#constants)
--
-- @since 0.0.1.0
foreign import capi "sodium.h value crypto_secretstream_xchacha20poly1305_TAG_MESSAGE"
  cryptoSecretStreamXChaCha20Poly1305TagMessage :: CUChar

-- | Indicates that the message marks the end of a set of messages, but not the end of the stream
--
-- /See:/ [crypto_secretstream_xchacha20poly1305_TAG_PUSH](https://doc.libsodium.org/secret-key_cryptography/secretstream#constants)
--
-- @since 0.0.1.0
foreign import capi "sodium.h value crypto_secretstream_xchacha20poly1305_TAG_PUSH"
  cryptoSecretStreamXChaCha20Poly1305TagPush :: CUChar

-- | "forget" the secret key used to encrypt this message and the previous ones, and derive a new secret key.
--
-- /See:/ [crypto_secretstream_xchacha20poly1305_TAG_REKEY](https://doc.libsodium.org/secret-key_cryptography/secretstream#constants)
--
-- @since 0.0.1.0
foreign import capi "sodium.h value crypto_secretstream_xchacha20poly1305_TAG_REKEY"
  cryptoSecretStreamXChaCha20Poly1305TagRekey :: CUChar

-- | Marks the end of the stream, and erases the secret key used to encrypt the previous sequence.
--
-- /See:/ [crypto_secretstream_xchacha20poly1305_TAG_FINAL](https://doc.libsodium.org/secret-key_cryptography/secretstream#constants)
--
-- @since 0.0.1.0
foreign import capi "sodium.h value crypto_secretstream_xchacha20poly1305_TAG_FINAL"
  cryptoSecretStreamXChaCha20Poly1305TagFinal :: CUChar
