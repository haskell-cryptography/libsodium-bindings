module Cryptography.Sodium.XChaCha20
  ( -- * Sizes
    xChaCha20KeySize,
    xChaCha20NonceSize,
  )
where

import qualified Cryptography.Sodium.XChaCha20.Direct as Direct

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
