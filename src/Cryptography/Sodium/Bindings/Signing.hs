{-# LANGUAGE CApiFFI #-}
{-# LANGUAGE Trustworthy #-}
{-# LANGUAGE TypeApplications #-}

-- |
-- Module: Cryptography.Sodium.Bindings.Signing
-- Description: Direct bindings to the public-key signing algorithm ed25519 implemented in Libsodium
-- Copyright: (C) Hécate Moonlight 2022
-- License: BSD-3-Clause
-- Maintainer: The Haskell Cryptography Group
-- Stability: Stable
-- Portability: GHC only
module Cryptography.Sodium.Bindings.Signing
  ( -- * Introduction
    -- $introduction

    -- * Key pair generation
    cryptoSignKeyPair,
    cryptoSignSeedKeyPair,

    -- * Combined mode
    cryptoSign,
    cryptoSignOpen,

    -- * Detached Mode
    -- $detachedMode
    cryptoSignDetached,
    cryptoSignVerifyDetached,

    -- * Multi-part messages
    -- $mpm
    CryptoSignState,
    withSignState,
    cryptoSignInit,
    cryptoSignUpdate,
    cryptoSignFinalCreate,
    cryptoSignFinalVerify,
    cryptoSignED25519SkToSeed,
    cryptoSignED25519SkToPk,

    -- * Constants
    cryptoSignStateBytes,
    cryptoSignPublicKeyBytes,
    cryptoSignSecretKeyBytes,
    cryptoSignBytes,
    cryptoSignSeedBytes,
  )
where

import Foreign (Ptr, allocaBytes)
import Foreign.C (CInt (..), CSize (..), CUChar (..), CULLong (..))

-- $introduction
--
-- When signing with public-key cryptography, a signer generates a key pair consisting of:
--
--   * A secret key, which you can use to append a signature to any number of messages.
--   * A public key, which anybody can use to verify that the signature appended to a
--     message was issued by the creator of the public key.
--
-- Verifiers need to already know and ultimately trust a public key before messages signed using
-- it can be verified.
--
-- Warning: this is different from authenticated encryption. Appending a signature does not change
-- the representation of the message itself.

-------------------------
-- Key pair generation --
-------------------------

-- | Randomly generate a secret key and a corresponding public key.
--
-- /See:/ [crypto_sign_keypair()](https://doc.libsodium.org/public-key_cryptography/public-key_signatures#key-pair-generation)
--
-- @since 0.0.1.0
foreign import capi "sodium.h crypto_sign_keypair"
  cryptoSignKeyPair ::
    -- | A pointer to the buffer holding the public key. It has a length of 'cryptoSignPublicKeyBytes' bytes.
    Ptr CUChar ->
    -- | A pointer to the buffer holding the secret key. It has a length of 'cryptoSignSecretKeyBytes' bytes.
    Ptr CUChar ->
    -- | Returns 0 on success, -1 on error.
    IO CInt

-- | Derive a keypair (secret key and public key) from a seed.
-- It is deterministic.
--
-- /See:/ [crypto_sign_seed_keypair()](https://doc.libsodium.org/public-key_cryptography/public-key_signatures#key-pair-generation)
--
-- @since 0.0.1.0
foreign import capi "sodium.h crypto_sign_seed_keypair"
  cryptoSignSeedKeyPair ::
    -- | A pointer to the buffer holding the public key. It has a length of 'cryptoSignPublicKeyBytes'.
    Ptr CUChar ->
    -- | A pointer to the buffer holding the secret key. It has a length of 'cryptoSignSecretKeyBytes'.
    Ptr CUChar ->
    -- | A pointer to the seed. It has a length of 'cryptoSignSeedBytes'.
    Ptr CUChar ->
    -- | Returns 0 on success, -1 on error.
    IO CInt

-------------------
-- Combined Mode --
-------------------

-- | Prepend a signature to a message, using the secret key.
--
-- The signed message, which includes the signature plus an unaltered copy of the message, is put
-- into the signed message buffer, and is of length 'cryptoSignBytes' + @length of the message@ bytes.
--
-- If the pointer to the length of the signed message is not a 'Foreign.nullPtr',
-- then the actual length of the signed message is stored in it.
--
-- /See:/ [crypto_sign()](https://doc.libsodium.org/public-key_cryptography/public-key_signatures#combined-mode)
--
-- @since 0.0.1.0
foreign import capi "sodium.h crypto_sign"
  cryptoSign ::
    -- | Pointer to the signed message.
    Ptr CUChar ->
    -- | Pointer to the length of the signed message.
    Ptr CULLong ->
    -- | Pointer to the message to sign.
    Ptr CUChar ->
    -- | Length of the message.
    CULLong ->
    -- | Pointer to the secret key.
    Ptr CUChar ->
    -- | Returns 0 on success, -1 on error.
    IO CInt

-- | Check that the signed message has a valid signature for the public key.
--
-- On success, it puts the message without the signature into, and stores its length in
-- the buffer holding the length of the message, if the pointer is not a 'Foreign.nullPtr'.
--
-- /See:/ [crypto_sign_open()](https://doc.libsodium.org/public-key_cryptography/public-key_signatures#key-pair-generation)
--
-- @since 0.0.1.0
foreign import capi "sodium.h crypto_sign_open"
  cryptoSignOpen ::
    -- | Pointer to the buffer holding the message without the signature.
    Ptr CUChar ->
    -- | Pointer to the buffer holding the length of the message, if it
    -- is not a 'Foreign.nullPtr'.
    Ptr CULLong ->
    -- | Pointer to the signed message.
    Ptr CUChar ->
    -- | Length of the signed message.
    CULLong ->
    -- | Pointer to the public key.
    Ptr CUChar ->
    -- | On success, the function returns 0
    -- If the signature isn't valid, then the function returns -1.
    IO CInt

-------------------
-- Detached Mode --
-------------------

-- $detachedMode
--
-- In detached mode, the signature is stored without attaching a copy of the original message to it.

-- | Sign the message using the secret key and put the signature into a buffer, which can be up to
-- 'cryptoSignBytes' bytes long.
-- The actual length of the signature is put into a buffer if its pointer is not 'Foreign.nullPtr'.
-- It is safe to ignore the length of the signature and always consider a signature as 'cryptoSignBytes' bytes long;
-- shorter signatures will be transparently padded with zeros if necessary.
--
-- /See:/ [crypto_sign_detached()](https://doc.libsodium.org/public-key_cryptography/public-key_signatures#detached-mode)
--
-- @since 0.0.1.0
foreign import capi "sodium.h crypto_sign_detached"
  cryptoSignDetached ::
    -- | Pointer to the signature.
    Ptr CUChar ->
    -- | Pointer to the length of the signature.
    Ptr CULLong ->
    -- | Pointer to the message to sign.
    Ptr CUChar ->
    -- | Length of the message.
    CULLong ->
    -- | Pointer to the secret key.
    Ptr CUChar ->
    -- | Returns 0 on success, -1 on error.
    IO CInt

-- | Verify that the signature is valid for the message, using the
-- signer's public key.
--
-- /See:/ [crypto_sign_verify_detached()](https://doc.libsodium.org/public-key_cryptography/public-key_signatures#detached-mode)
--
-- @since 0.0.1.0
foreign import capi "sodium.h crypto_sign_verify_detached"
  cryptoSignVerifyDetached ::
    -- | Pointer to the signature
    Ptr CUChar ->
    -- | Pointer to the message
    Ptr CUChar ->
    -- | Length of the message
    CULLong ->
    -- | Pointer to the signer's public key
    Ptr CUChar ->
    -- | Returns 0 on success, -1 on error.
    IO CInt

-------------------------
-- Multi-part messages --
-------------------------

-- $mpm
-- If the message you're trying to sign doesn't fit in memory, then it can be provided as a sequence
-- of arbitrarily-sized chunks.
-- This uses the @Ed25519ph@ signature system, which pre-hashes the message. In other words,
-- what gets signed is not the message itself but its image through a hash function. If the message
-- can fit in memory and be supplied as a single chunk, then the single-part API should be
-- preferred.
--
-- == Note
--
-- @Ed25519ph(m)@ is intentionally not equivalent to @Ed25519(SHA512(m))@. If, for
-- some reason, you need to pre-hash the message yourself, then use the multi-part
-- 'Cryptography.Sodium.Bindings.GenericHashing' module and sign the 512-bit output.

-- | Opaque tag representing the hash state struct @crypto_sign_state@ used by the C API.
--
-- It is of size 'cryptoSignStateBytes'.
--
-- To use a 'CryptoSignState', use 'withSignState'.
--
-- @since 0.0.1.0
data CryptoSignState

-- | Perform an operation with a 'CryptoSignState' of size 'cryptoSignStateBytes' allocated
-- and deallocated automatically.
--
-- ⚠ The return value of 'withSignState' __MUST NOT__ leak the 'CryptoSignState'.
--
-- Please refer to the documentation of 'Foreign.allocaBytes' for more operational details.
--
-- @since 0.0.1.0
withSignState :: (Ptr CryptoSignState -> IO a) -> IO a
withSignState action = do
  let size = (fromIntegral @CSize @Int) cryptoSignStateBytes
  allocaBytes size action

-- | Initialise the 'CryptoSignState' state.
--
-- It must be called before the first 'cryptoSignUpdate' call.
--
-- /See:/ [crypto_sign_init](https://doc.libsodium.org/public-key_cryptography/public-key_signatures#multi-part-messages)
--
-- @since 0.0.1.0
foreign import capi "sodium.h crypto_sign_init"
  cryptoSignInit ::
    -- | A pointer to the cryptographic state. Cannot be 'Foreign.nullPtr'.
    Ptr CryptoSignState ->
    -- | Returns 0 on success, -1 on error.
    IO CInt

-- | Add a new chunk to the message that will eventually be signed.
--
-- After all parts have been supplied, 'cryptoSignFinalCreate' or 'cryptoSignFinalVerify'
-- can be used.
--
-- /See:/ [crypto_sign_update](https://doc.libsodium.org/public-key_cryptography/public-key_signatures#multi-part-messages)
--
-- @since 0.0.1.0
foreign import capi "sodium.h crypto_sign_update"
  cryptoSignUpdate ::
    -- | A pointer to an initialized cryptographic state. Cannot be 'Foreign.nullPtr'.
    Ptr CryptoSignState ->
    -- | Pointer to the new chunk to sign.
    Ptr CUChar ->
    -- | Length of the new chunk.
    CULLong ->
    -- | Returns 0 on success, -1 on error.
    IO CInt

-- | Compute a signature for the previously supplied message
-- using the secret key, and put it into the signature buffer.
--
-- If the pointer to the length of the signature is not a 'Foreign.nullPtr',
-- then the length of the signature is stored at this address.
-- It is safe to ignore the length of the signature and always consider
-- a signature as 'cryptoSignBytes' bytes long;
-- shorter signatures will be transparently padded with zeros if necessary.
--
-- /See:/ [crypto_sign_final_create](https://doc.libsodium.org/public-key_cryptography/public-key_signatures#multi-part-messages)
--
-- @since 0.0.1.0
foreign import capi "sodium.h crypto_sign_final_create"
  cryptoSignFinalCreate ::
    -- | A pointer to an initialized cryptographic state. Cannot be 'Foreign.nullPtr'.
    Ptr CryptoSignState ->
    -- | Pointer to the signature. Cannot be 'Foreign.nullPtr'.
    Ptr CUChar ->
    -- | A pointer to the length of the signature. Can be 'Foreign.nullPtr'.
    Ptr CULLong ->
    -- | Pointer to the secret key. Cannot be 'Foreign.nullPtr'.
    Ptr CUChar ->
    -- | Returns 0 on success, -1 on error.
    IO CInt

-- | Verify that the signature is valid using the public key
-- for the message whose content has been previously supplied using 'cryptoSignUpdate'.
--
-- /See:/ [crypto_sign_final_verify](https://doc.libsodium.org/public-key_cryptography/public-key_signatures#multi-part-messages)
--
-- @since 0.0.1.0
foreign import capi "sodium.h crypto_sign_final_verify"
  cryptoSignFinalVerify ::
    -- | A pointer to an initialized cryptographic state. Cannot be 'Foreign.nullPtr'.
    Ptr CryptoSignState ->
    -- | Pointer to the signature.
    Ptr CUChar ->
    -- | Pointer to the public key.
    Ptr CUChar ->
    -- | Returns 0 on success, -1 on error.
    IO CInt

-- | This function extracts the seed from the
-- secret key secret key and copies it into the buffer holding the seed.
-- The size of the seed will be equal to 'cryptoSignSeedBytes'.
--
-- /See:/ [crypto_sign_ed25519_sk_to_seed](https://doc.libsodium.org/public-key_cryptography/public-key_signatures#extracting-the-seed-and-the-public-key-from-the-secret-key)
--
-- @since 0.0.1.0
foreign import capi "sodium.h crypto_sign_ed25519_sk_to_seed"
  cryptoSignED25519SkToSeed ::
    -- | Pointer to the seed.
    Ptr CUChar ->
    -- | Pointer to the secret key.
    Ptr CUChar ->
    -- | Returns 0 on success, -1 on error.
    IO CInt

-- | This function extracts the public key from the secret key secret key
-- and copies it into public key.
-- The size of public key will be equal to 'cryptoSignPublicKeyBytes'.
--
-- /See:/ [crypto_sign_ed25519_sk_to_pk](https://doc.libsodium.org/public-key_cryptography/public-key_signatures#extracting-the-seed-and-the-public-key-from-the-secret-key)
--
-- @since 0.0.1.0
foreign import capi "sodium.h crypto_sign_ed25519_sk_to_pk"
  cryptoSignED25519SkToPk ::
    -- | Pointer to the public key.
    Ptr CUChar ->
    -- | Pointer to the secret key.
    Ptr CUChar ->
    -- | Returns 0 on success, -1 on error.
    IO CInt

---------------
-- Constants --
---------------

-- | The amount of memory needed to store a 'CryptoSignState'.
--
-- @since 0.0.1.0
foreign import capi "sodium.h crypto_sign_statebytes"
  cryptoSignStateBytes :: CSize

-- | @since 0.0.1.0
foreign import capi "sodium.h value crypto_sign_PUBLICKEYBYTES"
  cryptoSignPublicKeyBytes :: CSize

-- | @since 0.0.1.0
foreign import capi "sodium.h value crypto_sign_SECRETKEYBYTES"
  cryptoSignSecretKeyBytes :: CSize

-- | @since 0.0.1.0
foreign import capi "sodium.h value crypto_sign_BYTES"
  cryptoSignBytes :: CSize

-- | @since 0.0.1.0
foreign import capi "sodium.h value crypto_sign_SEEDBYTES"
  cryptoSignSeedBytes :: CSize
