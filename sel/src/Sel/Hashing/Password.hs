{-# LANGUAGE DerivingStrategies #-}
{-# LANGUAGE NamedFieldPuns #-}
{-# LANGUAGE TypeApplications #-}

-- |
--
-- Module: Sel.Hashing.Password
-- Description: Password hashing with the Argon2id algorithm
-- Copyright: (C) Hécate Moonlight 2022
-- License: BSD-3-Clause
-- Maintainer: The Haskell Cryptography Group
-- Portability: GHC only
module Sel.Hashing.Password
  ( -- * Introduction
    -- $introduction
    PasswordHash

    -- ** Password Hashing and Verifying
  , hashByteString
  , hashText
  , verifyPassword
  , hashByteStringWithParams

    -- ** Conversion to textual formats
  , passwordHashToByteString
  , passwordHashToText

    -- * Salt
  , Salt
  , genSalt

    -- * Argon2 Parameters
  , Argon2Params (..)
  , defaultArgon2Params
  )
where

import Control.Monad (void)
import Data.ByteString (ByteString)
import qualified Data.ByteString.Internal as BS
import qualified Data.ByteString.Unsafe as BS
import Data.Text (Text)
import Data.Text.Display
import qualified Data.Text.Encoding as Text
import qualified Data.Text.Lazy.Builder as Builder
import Foreign hiding (void)
import Foreign.C
import GHC.IO.Handle.Text (memcpy)
import System.IO.Unsafe (unsafeDupablePerformIO)

import LibSodium.Bindings.PasswordHashing
import LibSodium.Bindings.Random

-- $introduction
--
-- This API provides functions for password hashing, backed by the Argon2id algorithm.
--
-- If you need to deviate from the defaults enforced by this module,
-- please use the underlying bindings at "LibSodium.Bindings.PasswordHashing".

-- |
--
-- @since 0.0.1.0
newtype PasswordHash = PasswordHash (ForeignPtr CChar)

-- | @since 0.0.1.0
instance Display PasswordHash where
  displayBuilder = Builder.fromText . passwordHashToText

-- | Hash a UTF8-encoded password with the Argon2id algorithm and
-- a set of pre-defined parameters.
--
-- @since 0.0.1.0
hashText :: Text -> IO PasswordHash
hashText text = hashByteString (Text.encodeUtf8 text)

-- | Hash the password with the Argon2id algorithm and
-- a set of pre-defined parameters.
--
-- @since 0.0.1.0
hashByteString :: ByteString -> IO PasswordHash
hashByteString bytestring =
  BS.unsafeUseAsCStringLen bytestring $ \(cString, cStringLen) -> do
    hashForeignPtr <- Foreign.mallocForeignPtrBytes (fromIntegral cryptoPWHashStrBytes)
    Foreign.withForeignPtr hashForeignPtr $ \passwordHashPtr ->
      void $
        cryptoPWHashStr
          passwordHashPtr
          cString
          (fromIntegral @Int @CULLong cStringLen)
          cryptoPWHashOpsLimitModerate
          cryptoPWHashMemLimitModerate
    pure $ PasswordHash hashForeignPtr

-- | Hash the password with the Argon2id algorithm.
--
-- The hash is __not__ encoded in human-readable format.
--
-- @since 0.0.1.0
hashByteStringWithParams :: Argon2Params -> Salt -> ByteString -> IO PasswordHash
hashByteStringWithParams Argon2Params{opsLimit, memLimit} (Salt argonSalt) bytestring =
  BS.unsafeUseAsCStringLen bytestring $ \(cString, cStringLen) -> do
    BS.unsafeUseAsCStringLen argonSalt $ \(saltString, _) -> do
      hashForeignPtr <- mallocForeignPtrBytes (fromIntegral cryptoPWHashStrBytes)
      withForeignPtr hashForeignPtr $ \passwordHashPtr ->
        void $
          cryptoPWHash
            passwordHashPtr
            (fromIntegral @CSize @CLLong cryptoPWHashStrBytes)
            cString
            (fromIntegral @Int @CULLong cStringLen)
            (castPtr saltString)
            opsLimit
            memLimit
            cryptoPWHashAlgDefault
      pure $ PasswordHash (castForeignPtr @CUChar @CChar hashForeignPtr)

-- | Verify the password hash against a clear 'Text' password
--
-- This function purposefully takes some time to complete, in order to alleviate bruteforce attacks.
--
-- @since 0.0.1.0
verifyText :: PasswordHash -> Text -> Bool
verifyText passwordHash clearTextPassword = verifyByteString passwordHash (Text.encodeUtf8 clearTextPassword)

-- | Verify the password hash against a clear 'ByteString' password
--
-- This function purposefully takes some time to complete, in order to alleviate bruteforce attacks.
--
-- @since 0.0.1.0
verifyByteString :: PasswordHash -> ByteString -> Bool
verifyByteString (PasswordHash fPtr) clearTextPassword = unsafeDupablePerformIO $ do
  BS.unsafeUseAsCStringLen clearTextPassword $ \(cString, cStringLen) -> do
    Foreign.withForeignPtr fPtr $ \hashPtr -> do
      result <-
        cryptoPWHashStrVerify
          hashPtr
          cString
          (fromIntegral @Int @CULLong cStringLen)
      pure $ result == 0

-- | Convert a 'PasswordHash' to a 'ByteString'.
--
-- @since 0.0.1.0
passwordHashToByteString :: PasswordHash -> ByteString
passwordHashToByteString (PasswordHash fPtr) =
  BS.fromForeignPtr (Foreign.castForeignPtr fPtr) 0 hashBytesSize
  where
    hashBytesSize = fromIntegral @CSize @Int cryptoPWHashStrBytes

-- | Convert a 'PasswordHash' to a 'Text.
--
-- @since 0.0.1.0
passwordHashToText :: PasswordHash -> Text
passwordHashToText = Text.decodeUtf8 . passwordHashToByteString

-- | The 'Salt' is used in conjunction with 'hashByteStringWithParams'
-- when you want to manually provide the piece of data that will
-- differentiate two fingerprints of the same password.
--
-- It is automatically taken care of for you when you use
-- 'hashByteString' or 'hashText'.
--
-- Use 'genSalt' to create a 'Salt' of size
-- equal to the constant 'cryptoPWHashSaltBytes'.
--
-- @since 0.0.1.0
newtype Salt = Salt ByteString

-- |
--
-- @since 0.0.1.0
data Argon2Params = Argon2Params
  { opsLimit :: CULLong
  , memLimit :: CSize
  }

-- | These are the default parameters with which 'hashByteStringWithParams' can be invoked:
--
-- * /opsLimit/ = 'cryptoPWHashOpsLimitModerate'
-- * /memLimit/ = 'cryptoPWHashMemLimitModerate'
--
-- @since 0.0.1.0
defaultArgon2Params :: Argon2Params
defaultArgon2Params =
  Argon2Params
    { opsLimit = cryptoPWHashOpsLimitModerate
    , memLimit = cryptoPWHashMemLimitModerate
    }

-- | Generate a random 'Salt' for password hashing
--
-- @since 0.0.1.0
genSalt :: IO Salt
genSalt = do
  saltForeignPtr <- BS.mallocByteString (fromIntegral cryptoPWHashSaltBytes)
  withForeignPtr saltForeignPtr $ \saltPtr -> do
    randombytesBuf saltPtr cryptoPWHashSaltBytes
    bsPtr <- mallocBytes (fromIntegral cryptoPWHashSaltBytes)
    memcpy bsPtr saltPtr cryptoPWHashSaltBytes
    Salt <$> BS.unsafePackMallocCStringLen (castPtr @Word8 @CChar bsPtr, fromIntegral cryptoPWHashSaltBytes)
