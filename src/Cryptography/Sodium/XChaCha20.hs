{-# LANGUAGE BangPatterns #-}

-- |
-- Module: Cryptography.Sodium.XChaCha20
-- Description: Thin Haskell wrappers for XChaCha20 primitives
-- Copyright: (C) Koz Ross 2022
-- License: BSD-3-Clause
-- Maintainer: koz.ross@retro-freedom.nz
-- Stability: Experimental
-- Portability: GHC only
--
-- Thin Haskell wrappers around XChaCha20 primitives. These are designed to be
-- friendlier and easier to use than the direct C bindings. If you need full
-- control, or want to use the direct close-to-C bindings, use
-- 'Cryptography.Sodium.XChaCha20.Direct'.
module Cryptography.Sodium.XChaCha20
  ( -- * Data types
    XChaCha20Key,

    -- * Sizes
    xChaCha20KeySize,
    xChaCha20NonceSize,
  )
where

import qualified Cryptography.Sodium.Helpers.Direct as Helpers
import qualified Cryptography.Sodium.XChaCha20.Direct as Direct
import Foreign.C.String (peekCString)
import Foreign.C.Types (CUChar)
import Foreign.ForeignPtr (ForeignPtr, withForeignPtr)
import Foreign.Marshal.Alloc (free, mallocBytes)
import Foreign.Ptr (Ptr)
import System.IO.Unsafe (unsafePerformIO)

-- | An XChaCha20 secret key. This is an \'opaque newtype\' providing some
-- Haskell conveniences; underneath, it's an array of bytes in C.
--
-- @since 1.0
newtype XChaCha20Key = XCC20K (ForeignPtr CUChar)

-- | Guaranteed constant-time.
--
-- @since 1.0
instance Eq XChaCha20Key where
  {-# NOINLINE (==) #-}
  XCC20K fp == XCC20K fp' =
    unsafePerformIO
      . withForeignPtr fp
      $ \p -> withForeignPtr fp' $ pure . go p
    where
      go :: Ptr CUChar -> Ptr CUChar -> Bool
      go p p' =
        let !res = Helpers.sodiumMemcmp p p' Direct.cryptoStreamXChaCha20KeyBytes
         in res == 0

-- | Displays the key in hex. Guaranteed constant-time.
--
-- @since 1.0
instance Show XChaCha20Key where
  {-# NOINLINE show #-}
  show (XCC20K fp) = unsafePerformIO . withForeignPtr fp $ go
    where
      go :: Ptr CUChar -> IO String
      go p = do
        let !binLen = Direct.cryptoStreamXChaCha20KeyBytes
        let !hexLen = binLen * 2 + 1
        outParam <- mallocBytes . fromIntegral $ hexLen
        _ <- Helpers.sodiumBinToHex outParam hexLen p binLen
        s <- peekCString outParam
        free outParam
        pure $ "XChacha20Key: " <> s

-- | The size of an XChaCha20 key, in bytes.
--
-- @since 1.0
xChaCha20KeySize :: Int
xChaCha20KeySize = fromIntegral Direct.cryptoStreamXChaCha20KeyBytes

-- | The size of an XChaCha20 nonce, in bytes.
--
-- @since 1.0
xChaCha20NonceSize :: Int
xChaCha20NonceSize = fromIntegral Direct.cryptoStreamXChaCha20NonceBytes
