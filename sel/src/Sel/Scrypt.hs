-- |
--
-- Module: Sel.Scrypt
-- Description: Hashing with the Scrypt algorithm.
-- Copyright: (C) Seth Paul Hubbard 2023
-- License: BSD-3-Clause
-- Maintainer: The Haskell Cryptography Group
-- Stability: Stable
-- Portability: GHC only
module Sel.Scrypt
  ( -- ** Introduction
    -- $introduction

    -- ** Password storage.
    ScryptHash
  , scryptStorePassword
  , scryptVerifyPassword
  )
where

import Control.Monad (void)
import Data.ByteString (StrictByteString)
import Data.ByteString.Unsafe (unsafeUseAsCStringLen)
import Foreign hiding (void)
import Foreign.C
import LibSodium.Bindings.Scrypt
import Sel.Internal
import System.IO.Unsafe (unsafeDupablePerformIO)

-- $introduction
--
-- This API is used for storing and verifying Scrypt-hashed passwords.
-- There are no bindings in this module for hashing passwords using Scrypt.
-- Please use the "Sel.Hashing.Password" module instead.

-- | A pointer to a password hashed using Scrypt.
--
-- @since 0.0.1.0
newtype ScryptHash = ScryptHash (ForeignPtr CChar)

instance Eq ScryptHash where
  (ScryptHash sh1) == (ScryptHash sh2) =
    unsafeDupablePerformIO $
      foreignPtrEq sh1 sh2 cryptoPWHashScryptSalsa2018SHA256StrBytes

instance Ord ScryptHash where
  compare (ScryptHash sh1) (ScryptHash sh2) =
    unsafeDupablePerformIO $
      foreignPtrOrd sh1 sh2 cryptoPWHashScryptSalsa2018SHA256StrBytes

-- | Store a password of size `cryptoPWHashScryptSalsa2018SHA256StrBytes`.
--
-- @since 0.0.1.0
scryptStorePassword :: StrictByteString -> IO ScryptHash
scryptStorePassword bytestring = do
  unsafeUseAsCStringLen bytestring $ \(cString, cStringLen) -> do
    hashForeignPtr <- mallocForeignPtrBytes (fromIntegral cryptoPWHashScryptSalsa2018SHA256StrBytes)
    withForeignPtr hashForeignPtr $ \hashPtr ->
      void $
        cryptoPWHashScryptSalsa2018SHA256Str
          hashPtr
          cString
          (fromIntegral cStringLen)
          (fromIntegral cryptoPWHashScryptSalsa2018SHA256OpsLimitInteractive)
          cryptoPWHashScryptSalsa2018SHA256MemLimitInteractive
    pure $ ScryptHash hashForeignPtr

-- | Verify a hashed password against its unhashed counterpart.
--
-- @since 0.0.1.0
scryptVerifyPassword :: StrictByteString -> ScryptHash -> IO Bool
scryptVerifyPassword bytestring (ScryptHash sh) = do
  unsafeUseAsCStringLen bytestring $ \(cString, cStringLen) -> do
    withForeignPtr sh $ \scryptHash -> do
      result <-
        cryptoPWHashScryptSalsa2018SHA256StrVerify
          scryptHash
          cString
          (fromIntegral cStringLen)
      return (result == 0)
