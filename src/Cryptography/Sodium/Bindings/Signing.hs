{-# LANGUAGE CApiFFI #-}
{-# LANGUAGE Trustworthy #-}

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
    cryptoSignDetached,

    -- * Multi-part messages
    -- $mpm
    CryptoSignState,
    cryptoSignStateBytes,
    withSignState,
    cryptoSignInit,
    cryptoSignUpdate,
    cryptoSignFinalCreate,
    cryptoSignFinalVerify,
    cryptoSignED25519SkToSeed,
    cryptoSignED25519SkToPk,

    -- * Constants
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
-- When signing with public-key cryptography,  a signer generates a key pair consisting of:
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

-- | This function randomly generates a secret key and a corresponding public key.
-- The public key is put into the @public key@ and the secret key into the @secret key@.
--
-- @since 0.0.1.0
foreign import capi "sodium.h crypto_sign_keypair"
  cryptoSignKeyPair ::
    -- | A pointer to an initialized cryptographic state. It has a length of 'cryptoSignPublicKeyBytes' bytes.
    Ptr CUChar ->
    -- | A pointer to an initialized cryptographic state. It has a length of 'cryptoSignSecretKeyBytes' bytes.
    Ptr CUChar ->
    -- | Return code is 0 on success, -1 on error.
    IO CInt

-- | This function derives a keypair (@secret key@ and @public key@) from a seed.
-- It is deterministic.
--
-- @since 0.0.1.0
foreign import capi "sodium.h crypto_sign_seed_keypair"
  cryptoSignSeedKeyPair ::
    -- | A pointer to an initialized cryptographic state. It has a length of 'cryptoSignPublicKeyBytes'.
    Ptr CUChar ->
    -- | A pointer to an initialized cryptographic state. It has a length of 'cryptoSignSecretKeyBytes'.
    Ptr CUChar ->
    -- | A pointer to an initialized cryptographic state. It has a length of 'cryptoSignSeedBytes'.
    Ptr CUChar ->
    -- | Return code is 0 on success, -1 on error.
    IO CInt

-------------------
-- Combined Mode --
-------------------

-- | The 'cryptoSign' function prepends a signature to a message @m@, whose length is @mlen@ bytes,
-- using the secret key @secret key@.
--
-- The signed message, which includes the signature plus an unaltered copy of the message, is put
-- into @signed message@ and is 'cryptoSignBytes' + @mlen@ bytes long.
--
-- If the pointer to the length of the signed message is not a 'Foreign.nullPtr',
-- then the actual length of the signed message is stored in it.
--
-- @since 0.0.1.0
foreign import capi "sodium.h crypto_sign"
  cryptoSign ::
    -- | Pointer to the @signed message@.
    Ptr CUChar ->
    -- | Pointer to the length of the @signed message@.
    Ptr CULLong ->
    -- | Pointer to the @message@ to sign.
    Ptr CUChar ->
    -- | Length of the @message@.
    CULLong ->
    -- | Pointer to the @secret key@.
    Ptr CUChar ->
    -- | Return code is 0 on success, -1 on error.
    IO CInt

-- | The 'cryptoSignOpen' function checks that the signed message @signed message@,
-- whose length is @smlen@ bytes, has a valid signature for the public key @public key@.
--
-- On success, it puts the message without the signature into @m@, stores its length in @mlen@
-- if @mlen@ is not a 'Foreign.nullPtr' pointer.
--
-- @since 0.0.1.0
foreign import capi "sodium.h crypto_sign_open"
  cryptoSignOpen ::
    -- | Pointer to the @message@ you wish to sign.
    Ptr CUChar ->
    -- | Pointer to the length of the @message@.
    Ptr CULLong ->
    -- | Pointer to the @signed message@.
    Ptr CUChar ->
    -- | Length of the signed message.
    CULLong ->
    -- | Pointer to the @public key@.
    Ptr CUChar ->
    -- | On success, the function returns 0
    -- If the signature isn't valid, then the function returns -1.
    IO CInt

-------------------
-- Detached Mode --
-------------------

-- | The 'cryptoSignDetached' function signs the message @m@, whose length is @mlen@ bytes,
-- using the secret key @secret key@ and puts the signature into @sig@, which can be up to
-- 'cryptoSignBytes' bytes long.
-- The actual length of the signature is put into @siglen@ if @siglen@ is not 'Foreign.nullPtr'.
-- It is safe to ignore @siglen@ and always consider a signature as 'cryptoSignBytes' bytes long;
-- shorter signatures will be transparently padded with zeros if necessary.
--
-- @since 0.0.1.0
foreign import capi "sodium.h crypto_sign_detached"
  cryptoSignDetached ::
    -- | Pointer to the @signature@.
    Ptr CUChar ->
    -- | Pointer to the length of the @signature@.
    Ptr CULLong ->
    -- | Pointer to the @message@ to sign.
    Ptr CUChar ->
    -- | Length of the @message@.
    CULLong ->
    -- | Pointer to the @secret key@.
    Ptr CUChar ->
    -- | Return code is 0 on success, -1 on error.
    IO CInt

-------------------------
-- Multi-part messages --
-------------------------

-- $mpm
-- If the message you're trying to sign doesn't fit in memory, then it can be provided as a sequence
-- of arbitrarily-sized
-- chunks. This uses the @Ed25519ph@ signature system, which pre-hashes the message. In other words,
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
  size <- fromIntegral <$> cryptoSignStateBytes
  allocaBytes size action

-- | The amount of memory needed to store a 'CryptoSignState'.
--
-- @since 0.0.1.0
foreign import capi "sodium.h crypto_sign_statebytes"
  cryptoSignStateBytes :: IO CSize

-- | This function initializes the 'CryptoSignState' state.
--
-- It must be called before the first 'cryptoSignUpdate' call.
--
-- @since 0.0.1.0
foreign import capi "sodium.h crypto_sign_init"
  cryptoSignInit ::
    -- | A pointer to an initialized cryptographic state. Cannot be 'Foreign.nullPtr'.
    Ptr CryptoSignState ->
    -- | Return code is 0 on success, -1 on error.
    IO CInt

-- | Add a new chunk to the message that will eventually be signed.
--
-- After all parts have been supplied, 'cryptoSignFinalCreate' or 'cryptoSignFinalVerify'
-- can be used.
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
    -- | Return code is 0 on success, -1 on error.
    IO CInt

-- | Compute a signature for the previously supplied message
-- using the @secret key@ and put it into the @signature@ buffer.
--
-- If the pointer to the length of the signature is not a 'Foreign.nullPtr',
-- then the length of the signature is stored at this address.
-- It is safe to ignore the length of the signature and always consider
-- a signature as 'cryptoSignBytes' bytes long;
-- shorter signatures will be transparently padded with zeros if necessary.
--
-- @since 0.0.1.0
foreign import capi "sodium.h crypto_sign_final_create"
  cryptoSignFinalCreate ::
    -- | A pointer to an initialized cryptographic state. Cannot be 'Foreign.nullPtr'.
    Ptr CryptoSignState ->
    -- | Pointer to the @signature@.
    Ptr CUChar ->
    -- | A pointer to an initialized cryptographic state. Can be 'Foreign.nullPtr'.
    Ptr CULLong ->
    -- | Pointer to the @secret key@.
    Ptr CUChar ->
    -- | Return code is 0 on success, -1 on error.
    IO CInt

-- | Verify that the @signature@ is valid using the @public key@
-- for the message whose content has been previously supplied using 'cryptoSignUpdate'.
--
-- @since 0.0.1.0
foreign import capi "sodium.h crypto_sign_final_verify"
  cryptoSignFinalVerify ::
    -- | A pointer to an initialized cryptographic state. Cannot be 'Foreign.nullPtr'.
    Ptr CryptoSignState ->
    -- | Pointer to the @signature@.
    Ptr CUChar ->
    -- | Pointer to the @public key@.
    Ptr CUChar ->
    -- | Return code is 0 on success, -1 on error.
    IO CInt

-- | This function extracts the seed from the
-- secret key @secret key@ and copies it into the buffer holding the @seed@.
-- The size of the @seed@ will be equal to 'cryptoSignSeedBytes'.
foreign import capi "sodium.h crypto_sign_ed25519_sk_to_seed"
  cryptoSignED25519SkToSeed ::
    -- | Pointer to the @seed@.
    Ptr CUChar ->
    -- | Pointer to the @secret key@.
    Ptr CUChar ->
    -- | Return code is 0 on success, -1 on error.
    IO CInt

-- | This function extracts the public key from the secret key @secret key@
-- and copies it into @public key@.
-- The size of @public key@ will be equal to 'cryptoSignPublicKeyBytes'.
--
-- @since 0.0.1.0
foreign import capi "sodium.h crypto_sign_ed25519_sk_to_pk"
  cryptoSignED25519SkToPk ::
    -- | Pointer to the @public key@.
    Ptr CUChar ->
    -- | Pointer to the @secret key@.
    Ptr CUChar ->
    -- | Return code is 0 on success, -1 on error.
    IO CInt

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
