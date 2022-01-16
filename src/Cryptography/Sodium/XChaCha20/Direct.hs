{-# LANGUAGE CApiFFI #-}

module Cryptography.Sodium.XChaCha20.Direct
  ( -- * Constants
    cryptoStreamXChaCha20KeyBytes,
    cryptoStreamXChaCha20NonceBytes,

    -- * Functions
    cryptoStreamXChaCha20,
    cryptoStreamXChaCha20Xor,
    cryptoStreamXChaCha20XorIC,
    cryptoStreamXChaCha20Keygen,
  )
where

import Data.Word (Word64)
import Foreign.C.Types
  ( CInt (CInt),
    CSize (CSize),
    CUChar,
    CULLong (CULLong),
  )
import Foreign.Ptr (Ptr)

-- | @since 1.0
foreign import capi "sodium.h crypto_stream_xchacha20"
  cryptoStreamXChaCha20 ::
    Ptr CUChar ->
    CULLong ->
    Ptr CUChar ->
    Ptr CUChar ->
    IO CInt

-- | @since 1.0
foreign import capi "sodium.h crypto_stream_xchacha20_xor"
  cryptoStreamXChaCha20Xor ::
    Ptr CUChar ->
    Ptr CUChar ->
    CULLong ->
    Ptr CUChar ->
    Ptr CUChar ->
    IO CInt

-- | @since 1.0
foreign import capi "sodium.h crypto_stream_xchacha20_xor_ic"
  cryptoStreamXChaCha20XorIC ::
    Ptr CUChar ->
    Ptr CUChar ->
    CULLong ->
    Ptr CUChar ->
    Word64 ->
    Ptr CUChar ->
    IO CInt

-- | @since 1.0
foreign import capi "sodium.h crypto_stream_xchacha20_keygen"
  cryptoStreamXChaCha20Keygen ::
    Ptr CUChar ->
    IO ()

-- | @since 1.0
foreign import capi "sodium.h value crypto_stream_xchacha20_KEYBYTES"
  cryptoStreamXChaCha20KeyBytes :: CSize

-- | @since 1.0
foreign import capi "sodium.h value crypto_stream_xchacha20_NONCEBYTES"
  cryptoStreamXChaCha20NonceBytes :: CSize
