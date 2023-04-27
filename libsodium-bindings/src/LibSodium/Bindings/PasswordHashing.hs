{-# LANGUAGE CApiFFI #-}
{-# LANGUAGE Trustworthy #-}

-- |
--
-- Module: LibSodium.Bindings.PasswordHashing
-- Description: Direct bindings to the password hashing primitives of Libsodium.
-- Copyright: (C) Hécate Moonlight 2022
-- License: BSD-3-Clause
-- Maintainer: The Haskell Cryptography Group
-- Stability: Stable
-- Portability: GHC only
module LibSodium.Bindings.PasswordHashing
  ( -- * Introduction
    -- $introduction

    -- * Operations
    cryptoPWHash
  , cryptoPWHashStr
  , cryptoPWHashStrVerify
  , cryptoPWHashStrNeedsRehash

    -- * Constants
  , cryptoPWHashAlgDefault
  , cryptoPWHashAlgArgon2I13
  , cryptoPWHashAlgArgon2ID13
  , cryptoPWHashSaltBytes
  , cryptoPWHashPasswdMin
  , cryptoPWHashPasswdMax
  , cryptoPWHashOpsLimitInteractive
  , cryptoPWHashOpsLimitSensitive
  , cryptoPWHashOpsLimitModerate
  , cryptoPWHashOpsLimitMin
  , cryptoPWHashOpsLimitMax
  , cryptoPWHashMemLimitModerate
  , cryptoPWHashMemLimitInteractive
  , cryptoPWHashMemLimitSensitive
  , cryptoPWHashMemLimitMin
  , cryptoPWHashMemLimitMax
  , cryptoPWHashBytesMax
  , cryptoPWHashBytesMin
  , cryptoPWHashStrBytes
  )
where

import Foreign (Ptr)
import Foreign.C (CChar, CInt (CInt), CLLong (CLLong), CSize (CSize), CUChar, CULLong (CULLong))

-- $introduction
-- This modules provides an API that can be used both for key derivation using a low-entropy input and password storage.
--
-- === Guidelines for choosing the parameters
-- Start by determining how much memory the function can use.
-- What will be the highest number of threads/processes evaluating the function simultaneously
-- (ideally, no more than 1 per CPU core)? How much physical memory is guaranteed to be available?
--
-- Set @memlimit@ to the amount of memory you want to reserve for password hashing.
--
-- Then set @opslimit@ to 3 and measure the time it takes to hash a password.
--
-- If this is way too long for your application, reduce @memlimit@, but keep @opslimit@ set to 3.
--
-- If the function is so fast that you can afford it to be more computationally intensive without
-- any usability issues, then increase @opslimit@.
--
-- For online use (e.g. logging in on a website), a 1 second computation is likely to be the
-- acceptable maximum.
--
-- For interactive use (e.g. a desktop application), a 5 second pause after having entered a
-- password is acceptable if the password doesn't need to be entered more than once per session.
--
-- For non-interactive and infrequent use (e.g. restoring an encrypted backup),
-- an even slower computation can be an option.
--
-- However, the best defense against brute-force password cracking is to use strong passwords.
-- Libraries such as [passwdqc](http://www.openwall.com/passwdqc/) can help enforce this.

-- | This functions derives a key from a password. The computed key is then stored in the @out@ parameter.
--
-- @since 0.0.1.0
foreign import capi "sodium.h crypto_pwhash"
  cryptoPWHash
    :: Ptr CUChar
    -- ^ @out@ parameter. It represents the address of a dedicated storage area of @outlen@ bytes.
    -> CLLong
    -- ^ @outlen@ parameter. It is the length of the key derived from the @passwd@ parameter.
    -- This should be a least 'cryptoPWHashBytesMin' and at most 'cryptoPWHashBytesMax'.
    -> Ptr CChar
    -- ^ @passwd@ parameter. It is a pointer to the password that is to be derived.
    -> CULLong
    -- ^ @passwdlen@ parameter. It is the size of the password.
    -> Ptr CUChar
    -- ^ @salt@ parameter. It is of a fixed length established by 'cryptoPWHashSaltBytes'. It should be unpredictable.
    -- 'LibSodium.Bindings.Random.randombytesBuf' is the best way to fill the 'cryptoPWHashSaltBytes' of the
    -- salt.
    -> CULLong
    -- ^ @opslimit@ parameter. It represents the maximum amount of computations to perform. Raising this number will make the function require more CPU cycles
    -- to compute a key. This number must be between 'cryptoPWHashOpsLimitMin' and 'cryptoPWHashOpsLimitMax'.
    -> CSize
    -- ^ @memlimit@ parameter. It is the maximum amount of RAM in bytes that the function will use.
    -- This number must be between 'cryptoPWHashMemLimitMin' 'cryptoPWHashMemLimitMax'
    -> CInt
    -- ^ @alg@ parameter. It is an identifier for the algorithm to use and should be set to one of the following values:
    --     'cryptoPWHashAlgDefault', 'cryptoPWHashAlgArgon2I13' or 'cryptoPWHashAlgArgon2ID13'.
    -> IO CInt
    -- ^ The return code is 0 on success and -1 if the computation didn't complete,
    -- usually because the operating system refused to allocate the amount of requested memory.

-- | This function is used for password storage, like an SQL database.
-- It stores an ASCII-encoded string into its @out@ parameter,
-- which includes:
--
--   * The result of a memory-hard, CPU-intensive hash function applied to the password passwd of length passwdlen;
--   * The automatically generated salt used for the previous computation;
--   * The other parameters required to verify the password, including the algorithm identifier, its version, opslimit, and memlimit.
--
-- The @out@ parameter must be a dedicated storage area that's large enough to hold 'cryptoPWHashStrBytes' bytes,
-- but the actual output string may be shorter.
--
-- @since 0.0.1.0
foreign import capi "sodium.h crypto_pwhash_str"
  cryptoPWHashStr
    :: Ptr CChar
    -- ^ @out@ parameter. It must be of size 'cryptoPWHashStrBytes'.
    -> Ptr CChar
    -- ^ @passwd@ parameter. Points to a password to be stored.
    -> CULLong
    -- ^ @passwdlen@ parameter. Length of the password.
    -> CULLong
    -- ^ @opslimit@ parameter. It represents the maximum amount of computations to perform.
    -> CSize
    -- ^ @memlimit@ parameter. It is the maximum amount of RAM in bytes that the function will use.
    -> IO CInt
    -- ^ The function returns 0 on success and -1 if it didn't complete successfully.

-- | This function verifies that the @str@ parameter is a valid password verification string
-- (as generated by 'cryptoPWHashStr'), for a @passwd@ whose length is @passwdlen@.
--
-- @since 0.0.1.0
foreign import capi "sodium.h crypto_pwhash_str_verify"
  cryptoPWHashStrVerify
    :: Ptr CChar
    -- ^ @str@ parameter. It must be zero-terminated.
    -> Ptr CChar
    -- ^ @passwd@ parameter.
    -> CULLong
    -- ^ @passwdlen@ parameter.
    -> IO CInt
    -- ^ It returns 0 if the verification succeeds and -1 on error.

-- | This functions checks if a password verification string @str@ matches the parameters @opslimit@, @memlimit@, and the current default algorithm.
--
-- @since 0.0.1.0
foreign import capi "sodium.h crypto_pwhash_str_needs_rehash"
  cryptoPWHashStrNeedsRehash
    :: Ptr CChar
    -- ^ @str@ parameter.
    -> CULLong
    -- ^ @opslimit@ parameter.
    -> CSize
    -- ^ @memlimit@ parameter.
    -> IO CInt
    -- ^ The function returns 0 if the parameters already match the given ones, and returns 1 on error. In particular, It will return 1 if the string appears to be correct but doesn't match the given parameters. In that situation, applications may want to compute a new hash using the current parameters the next time the user logs in.

-- | Haskell binding to the @crypto_pwhash_ALG_DEFAULT@ constant.
--
-- @since 0.0.1.0
foreign import capi "sodium.h value crypto_pwhash_ALG_DEFAULT"
  cryptoPWHashAlgDefault :: CInt

-- | Haskell binding to the @crypto_pwhash_ALG_ARGON2I13@ constant.
--
-- @since 0.0.1.0
foreign import capi "sodium.h value crypto_pwhash_ALG_ARGON2I13"
  cryptoPWHashAlgArgon2I13 :: CInt

-- | Haskell binding to the @crypto_pwhash_ALG_ARGON2ID13@ constant.
--
-- @since 0.0.1.0
foreign import capi "sodium.h value crypto_pwhash_ALG_ARGON2ID13"
  cryptoPWHashAlgArgon2ID13 :: CInt

-- | Haskell binding to the @crypto_pwhash_SALTBYTES@ constant.
--
--  @since 0.0.1.0
foreign import capi "sodium.h value crypto_pwhash_SALTBYTES"
  cryptoPWHashSaltBytes :: CSize

-- | Haskell binding to the @crypto_pwhash_PASSWD_MIN@ constant.
--
-- @since 0.0.1.0
foreign import capi "sodium.h value crypto_pwhash_PASSWD_MIN"
  cryptoPWHashPasswdMin :: CSize

-- | Haskell binding to the @crypto_pwhash_PASSWD_MAX@ constant.
--
--  @since 0.0.1.0
foreign import capi "sodium.h value crypto_pwhash_PASSWD_MAX"
  cryptoPWHashPasswdMax :: CSize

-- | Haskell binding to the @crypto_pwhash_OPSLIMIT_INTERACTIVE@ constant.
--
--  @since 0.0.1.0
foreign import capi "sodium.h value crypto_pwhash_OPSLIMIT_INTERACTIVE"
  cryptoPWHashOpsLimitInteractive :: CULLong

-- | Haskell binding to the @crypto_pwhash_OPSLIMIT_SENSITIVE@ constant.
--
--  @since 0.0.1.0
foreign import capi "sodium.h value crypto_pwhash_OPSLIMIT_SENSITIVE"
  cryptoPWHashOpsLimitSensitive :: CULLong

-- | Haskell binding to the @crypto_pwhash_OPSLIMIT_MODERATE@ constant.
--
--  @since 0.0.1.0
foreign import capi "sodium.h value crypto_pwhash_OPSLIMIT_MODERATE"
  cryptoPWHashOpsLimitModerate :: CULLong

-- | Haskell binding to the @crypto_pwhash_OPSLIMIT_MIN@ constant.
--
-- @since 0.0.1.0
foreign import capi "sodium.h value crypto_pwhash_OPSLIMIT_MIN"
  cryptoPWHashOpsLimitMin :: CULLong

-- | Haskell binding to the @crypto_pwhash_OPSLIMIT_MAX@ constant.
--
-- @since 0.0.1.0
foreign import capi "sodium.h value crypto_pwhash_OPSLIMIT_MAX"
  cryptoPWHashOpsLimitMax :: CULLong

-- | Haskell binding to the @crypto_pwhash_MEMLIMIT_MODERATE@ constant.
--
-- @since 0.0.1.0
foreign import capi "sodium.h value crypto_pwhash_MEMLIMIT_MODERATE"
  cryptoPWHashMemLimitModerate :: CSize

-- | Haskell binding to the @crypto_pwhash_MEMLIMIT_INTERACTIVE@ constant.
--
-- @since 0.0.1.0
foreign import capi "sodium.h value crypto_pwhash_MEMLIMIT_INTERACTIVE"
  cryptoPWHashMemLimitInteractive :: CSize

-- | Haskell binding to the @crypto_pwhash_MEMLIMIT_SENSITIVE@ constant.
--
-- @since 0.0.1.0
foreign import capi "sodium.h value crypto_pwhash_MEMLIMIT_SENSITIVE"
  cryptoPWHashMemLimitSensitive :: CSize

-- | Haskell binding to the @crypto_pwhash_MEMLIMIT_MIN@ constant.
--
-- @since 0.0.1.0
foreign import capi "sodium.h value crypto_pwhash_MEMLIMIT_MIN"
  cryptoPWHashMemLimitMin :: CSize

-- | Haskell binding to the @crypto_pwhash_MEMLIMIT_MAX@ constant.
--
-- @since 0.0.1.0
foreign import capi "sodium.h value crypto_pwhash_MEMLIMIT_MAX"
  cryptoPWHashMemLimitMax :: CSize

-- | Haskell binding to the @crypto_pwhash_BYTES_MAX@ constant.
--
-- @since 0.0.1.0
foreign import capi "sodium.h value crypto_pwhash_BYTES_MAX"
  cryptoPWHashBytesMax :: CULLong

-- | Haskell binding to the @crypto_pwhash_BYTES_MIN@ constant.
--
-- @since 0.0.1.0
foreign import capi "sodium.h value crypto_pwhash_BYTES_MIN"
  cryptoPWHashBytesMin :: CULLong

-- | Haskell binding to the @crypto_pwhash_STRBYTES@ constant.
--
-- @since 0.0.1.0
foreign import capi "sodium.h value crypto_pwhash_STRBYTES"
  cryptoPWHashStrBytes :: CSize
