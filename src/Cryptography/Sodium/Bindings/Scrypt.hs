{-# LANGUAGE CApiFFI #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE Trustworthy #-}

-- |
--
-- Module: Cryptography.Sodium.Bindings.Scrypt
-- Description: Direct bindings to the scrypt password hashing function.
-- Copyright: (C) Hécate Moonlight 2022
-- License: BSD-3-Clause
-- Maintainer: The Haskell Cryptography Group
-- Stability: Stable
-- Portability: GHC only
module Cryptography.Sodium.Bindings.SHA2
  ( -- * Introduction
    -- $introduction
    cryptoPWHashScryptSalsa2018SHA256,

    -- * Password storage
    cryptoPWHashScryptSalsa2018SHA256Str,

    -- * Constants
    cryptoPWHashScryptSalsa2018SHA256BytesMin,
    cryptoPWHashScryptSalsa2018SHA256BytesMax,
    cryptoPWHashScryptSalsa2018SHA256PasswdMin,
    cryptoPWHashScryptSalsa2018SHA256PasswdMax,
    cryptoPWHashScryptSalsa2018SHA256SaltBytes,
    cryptoPWHashScryptSalsa2018SHA256StrBytes,
    cryptoPWHashScryptSalsa2018SHA256StrPrefix,
    cryptoPWHashScryptSalsa2018SHA256OpsLimitMin,
    cryptoPWHashScryptSalsa2018SHA256OpsLimitMax,
    cryptoPWHashScryptSalsa2018SHA256MemLimitMin,
    cryptoPWHashScryptSalsa2018SHA256MemLimitMax,
    cryptoPWHashScryptSalsa2018SHA256OpsLimitInteractive,
    cryptoPWHashScryptSalsa2018SHA256MemLimitInteractive,
    cryptoPWHashScryptSalsa2018SHA256OpsLimitSensitive,
    cryptoPWHashScryptSalsa2018SHA256MemLimitSensitive,
  )
where

import Foreign (Ptr)
import Foreign.C (CChar (..), CInt (CInt), CSize (CSize), CUChar, CULLong (CULLong))

-- $introduction
-- This is an implementation of the scrypt password hashing function.
-- However, unless you have specific reasons to use scrypt, you *should* instead consider the default function Argon2.

-- | Derive a key from a password.
--
-- For interactive, online operations, 'cryptoPWHashScryptSalsa2018SHA256OpsLimitInteractive'
-- and 'cryptoPWHashScryptSalsa2018SHA256MemLimitInteractive' provide a safe baseline to be used.
-- However, using higher values may improve security.
--
-- For highly sensitive data, 'cryptoPWHashScryptSalsa2018SHA256OpsLimitSensitive' and
-- 'cryptoPWHashScryptSalsa2018SHA256MemLimitSensitive' can be used as an alternative.
-- However, with these parameters, deriving a key takes about
-- 2 seconds on a 2.8 GHz Core i7 CPU and requires up to 1 GiB of dedicated RAM.
--
-- The salt should be unpredictable. 'Cryptography.Sodium.Bindings.Random.randombytesBuf'
-- is the easiest way to fill the 'cryptoPWHashScryptSalsa2018SHA256SaltBytes' bytes
-- of the salt.
--
-- Keep in mind that to produce the same key from the same password, the same salt,
-- opslimit, and memlimit values must be used. Therefore, these parameters must be stored for each user.
--
-- /See also:/ [crypto_pwhash_scryptsalsa208sha256()](https://doc.libsodium.org/advanced/scrypt#key-derivation)
--
-- @since 0.0.1.0
foreign import capi "sodium.h crypto_pwhash_scryptsalsa208sha256"
  cryptoPWHashScryptSalsa2018SHA256 ::
    -- | A pointer to the computed key.
    Ptr CUChar ->
    -- | The length of the computer key.
    -- Should be comprised between 'cryptoPWHashScryptSalsa2018SHA256BytesMin'
    -- and 'cryptoPWHashScryptSalsa2018SHA256BytesMax' (~127 GB).
    CULLong ->
    -- | A pointer to the password from which the key is derived
    Ptr CChar ->
    -- | The length of the password.
    -- Should be comprised between 'cryptoPWHashScryptSalsa2018SHA256PasswdMin'
    -- and 'cryptoPWHashScryptSalsa2018SHA256PasswdMax'.
    CChar ->
    -- | The salt, of length 'crypto_pwhash_scryptsalsa208sha256_SALTBYTES'.
    Ptr CUChar ->
    -- | The maximum amount of computations to perform.
    -- Raising this number will make the function require more CPU cycles to
    -- compute a key.
    -- Must be comprised between 'cryptoPWHashScryptSalsa2018SHA256OpsLimitMin'
    -- and 'cryptoPWHashScryptSalsa2018SHA256OpsLimitMax'.
    CULLong ->
    -- | The maximum amount of RAM in bytes that the function will use.
    -- It is highly recommended to allow the function to use at least 16 MiB.
    -- This number must be between 'cryptoPWHashScryptSalsa2018SHA256MemLimitMin'
    -- and 'cryptoPWHashScryptSalsa2018SHA256MemLimitMax'.
    CSize ->
    -- | Returns 0 on success, -1 if the computation didn't complete,
    -- usually because the operating system refused to allocate the amount of
    -- requested memory.
    IO CInt

-- | Generate an C ASCII encoded string which includes:
--
-- * The result of a memory-hard, CPU-intensive hash function applied to the password;
-- * The automatically generated salt used for the previous computation;
-- * The other parameters required to verify the password: opslimit and memlimit.
--
-- The constants 'cryptoPWHashScryptSalsa2018SHA256OpsLimitInteractive' and
-- 'cryptoPWHashScryptSalsa2018SHA256MemLimitInteractive' are safe baseline values to use.
--
-- @since 0.0.1.0
foreign import capi "sodium.h crypto_pwhash_scryptsalsa208sha256_str"
  cryptoPWHashScryptSalsa2018SHA256Str ::
    -- | A pointer to the buffer where the string
    Ptr CChar ->
    -- | The password
    Ptr CChar ->
    -- | Password length
    CULLong ->
    -- | Returns 0 on success, -1 on error.
    IO CInt

---------------
-- Constants --
---------------

-- | @since 0.0.1.0
foreign import capi "sodium.h value crypto_pwhash_scryptsalsa208sha256_BYTES_MIN"
  cryptoPWHashScryptSalsa2018SHA256BytesMin :: CSize

-- | @since 0.0.1.0
foreign import capi "sodium.h value crypto_pwhash_scryptsalsa208sha256_BYTES_MAX"
  cryptoPWHashScryptSalsa2018SHA256BytesMax :: CSize

-- | @since 0.0.1.0
foreign import capi "sodium.h value crypto_pwhash_scryptsalsa208sha256_PASSWD_MIN"
  cryptoPWHashScryptSalsa2018SHA256PasswdMin :: CSize

-- | @since 0.0.1.0
foreign import capi "sodium.h value crypto_pwhash_scryptsalsa208sha256_PASSWD_MAX"
  cryptoPWHashScryptSalsa2018SHA256PasswdMax :: CSize

-- | @since 0.0.1.0
foreign import capi "sodium.h value crypto_pwhash_scryptsalsa208sha256_SALTBYTES"
  cryptoPWHashScryptSalsa2018SHA256SaltBytes :: CSize

-- | @since 0.0.1.0
foreign import capi "sodium.h value crypto_pwhash_scryptsalsa208sha256_STRBYTES"
  cryptoPWHashScryptSalsa2018SHA256StrBytes :: CSize

-- | @since 0.0.1.0
foreign import capi "sodium.h value crypto_pwhash_scryptsalsa208sha256_STRPREFIX"
  cryptoPWHashScryptSalsa2018SHA256StrPrefix :: CSize

-- | @since 0.0.1.0
foreign import capi "sodium.h value crypto_pwhash_scryptsalsa208sha256_OPSLIMIT_MIN"
  cryptoPWHashScryptSalsa2018SHA256OpsLimitMin :: CSize

-- | @since 0.0.1.0
foreign import capi "sodium.h value crypto_pwhash_scryptsalsa208sha256_OPSLIMIT_MAX"
  cryptoPWHashScryptSalsa2018SHA256OpsLimitMax :: CSize

-- | @since 0.0.1.0
foreign import capi "sodium.h value crypto_pwhash_scryptsalsa208sha256_MEMLIMIT_MIN"
  cryptoPWHashScryptSalsa2018SHA256MemLimitMin :: CSize

-- | @since 0.0.1.0
foreign import capi "sodium.h value crypto_pwhash_scryptsalsa208sha256_MEMLIMIT_MAX"
  cryptoPWHashScryptSalsa2018SHA256MemLimitMax :: CSize

-- | @since 0.0.1.0
foreign import capi "sodium.h value crypto_pwhash_scryptsalsa208sha256_OPSLIMIT_INTERACTIVE"
  cryptoPWHashScryptSalsa2018SHA256OpsLimitInteractive :: CSize

-- | @since 0.0.1.0
foreign import capi "sodium.h value crypto_pwhash_scryptsalsa208sha256_MEMLIMIT_INTERACTIVE"
  cryptoPWHashScryptSalsa2018SHA256MemLimitInteractive :: CSize

-- | @since 0.0.1.0
foreign import capi "sodium.h value crypto_pwhash_scryptsalsa208sha256_OPSLIMIT_SENSITIVE"
  cryptoPWHashScryptSalsa2018SHA256OpsLimitSensitive :: CSize

-- | @since 0.0.1.0
foreign import capi "sodium.h value crypto_pwhash_scryptsalsa208sha256_MEMLIMIT_SENSITIVE"
  cryptoPWHashScryptSalsa2018SHA256MemLimitSensitive :: CSize
