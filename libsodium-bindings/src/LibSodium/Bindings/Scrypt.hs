{-# LANGUAGE CApiFFI #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE Trustworthy #-}
{-# OPTIONS_GHC -Wno-unused-imports #-}

-- |
--
-- Module: LibSodium.Bindings.Scrypt
-- Description: Direct bindings to the scrypt password hashing function.
-- Copyright: (C) Hécate Moonlight 2022
-- License: BSD-3-Clause
-- Maintainer: The Haskell Cryptography Group
-- Stability: Stable
-- Portability: GHC only
module LibSodium.Bindings.Scrypt
  ( -- * Introduction
    -- $introduction

    -- * Key Derivation
    cryptoPWHashScryptSalsa2018SHA256

    -- * Password storage
  , cryptoPWHashScryptSalsa2018SHA256Str
  , cryptoPWHashScryptSalsa2018SHA256StrVerify

    -- * Constants
  , cryptoPWHashScryptSalsa2018SHA256BytesMin
  , cryptoPWHashScryptSalsa2018SHA256BytesMax
  , cryptoPWHashScryptSalsa2018SHA256PasswdMin
  , cryptoPWHashScryptSalsa2018SHA256PasswdMax
  , cryptoPWHashScryptSalsa2018SHA256SaltBytes
  , cryptoPWHashScryptSalsa2018SHA256StrBytes
  , cryptoPWHashScryptSalsa2018SHA256StrPrefix
  , cryptoPWHashScryptSalsa2018SHA256OpsLimitMin
  , cryptoPWHashScryptSalsa2018SHA256OpsLimitMax
  , cryptoPWHashScryptSalsa2018SHA256MemLimitMin
  , cryptoPWHashScryptSalsa2018SHA256MemLimitMax
  , cryptoPWHashScryptSalsa2018SHA256OpsLimitInteractive
  , cryptoPWHashScryptSalsa2018SHA256MemLimitInteractive
  , cryptoPWHashScryptSalsa2018SHA256OpsLimitSensitive
  , cryptoPWHashScryptSalsa2018SHA256MemLimitSensitive
  )
where

import Foreign (Ptr)
import Foreign.C (CChar (CChar), CInt (CInt), CSize (CSize), CUChar, CULLong (CULLong))

-- $introduction
-- This is an implementation of the scrypt password hashing function.
-- However, unless you have specific reasons to use scrypt, you __should__ instead consider the default function Argon2.
--
-- == Glossary
--
-- * /opslimit/: The maximum amount of computations to perform. Raising this number will make the function require more CPU cycles to compute a key.
-- * /memlimit/: The maximum amount of RAM in bytes that the function will use.
--
-- == Guidelines for choosing scrypt parameters
--
-- Start by determining how much memory the scrypt function can use.
--
-- * What will be the highest number of threads/processes evaluating the function
-- simultaneously (ideally, no more than 1 per CPU core)?
--
-- * How much physical memory is guaranteed to be available?
-- The /memlimit/ parameter should be a power of 2.
--
-- Do not use anything less than 16 MiB, even for interactive use.
-- A reasonable starting point for /opslimit/ is @memlimit / 32@.
-- Measure how long the scrypt function needs to hash a password.
-- If this is way too long for your application, reduce /memlimit/ and adjust /opslimit/ using the above formula.
-- If the function is so fast that you can afford it to be more computationally intensive without any usability issues, increase /opslimit/. For online use (e.g.
-- logging in on a website), a 1 second computation is likely to be the acceptable maximum. For interactive use (e.g. a desktop application), a 5 second
-- pause after having entered a password is acceptable if the password doesn't need to be entered more than once per session. For non-interactive and
-- infrequent use (e.g. restoring an encrypted backup), an even slower computation can be an option. However, the best defense against brute-force password
-- cracking is to use strong passwords. Libraries such as [passwdqc](https://www.openwall.com/passwdqc/) can help enforce this.
--
-- == Notes
--
-- Do not use constants to verify a password or produce a deterministic output.
-- Save the parameters alongside the hash instead.
-- By doing so, passwords can be rehashed using different parameters if required later on.
--
-- By design, a password whose length is 65 bytes or more is reduced to SHA-256(password).
-- This can have security implications if the password is present in another password database
-- using raw, unsalted SHA-256 or when upgrading passwords previously hashed with unsalted SHA-256 to scrypt.
--
-- It is highly recommended to use 'LibSodium.Bindings.SecureMemory.lock'
-- to lock memory regions storing plaintext passwords and to call
-- 'LibSodium.Bindings.SecureMemory.unlock' right after
-- 'cryptoPWHashScryptSalsa2018SHA256Str' and 'cryptoPWHashScryptSalsa2018SHA256StrVerify'
-- return.

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
-- The salt should be unpredictable. 'LibSodium.Bindings.Random.randombytesBuf'
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
  cryptoPWHashScryptSalsa2018SHA256
    :: Ptr CUChar
    -- ^ A pointer to the computed key.
    -> CULLong
    -- ^ The length of the computed key.
    -- Should be  between 'cryptoPWHashScryptSalsa2018SHA256BytesMin'
    -- and 'cryptoPWHashScryptSalsa2018SHA256BytesMax' (~127 GB).
    -> Ptr CChar
    -- ^ A pointer to the password from which the key is derived
    -> CULLong
    -- ^ The length of the password.
    -- Should be between 'cryptoPWHashScryptSalsa2018SHA256PasswdMin'
    -- and 'cryptoPWHashScryptSalsa2018SHA256PasswdMax'.
    -> Ptr CUChar
    -- ^ The salt, of length 'cryptoPWHashScryptSalsa2018SHA256SaltBytes'.
    -> CULLong
    -- ^ /opslimit:/ The maximum amount of computations to perform.
    -- Must be between 'cryptoPWHashScryptSalsa2018SHA256OpsLimitMin'
    -- and 'cryptoPWHashScryptSalsa2018SHA256OpsLimitMax'.
    -> CSize
    -- ^ /memlimit:/ The maximum amount of RAM in bytes that the function will use.
    -- It is highly recommended to allow the function to use at least 16 MiB.
    -- This number must be between 'cryptoPWHashScryptSalsa2018SHA256MemLimitMin'
    -- and 'cryptoPWHashScryptSalsa2018SHA256MemLimitMax'.
    -> IO CInt
    -- ^ Returns 0 on success, -1 if the computation didn't complete,
    -- usually because the operating system refused to allocate the amount of
    -- requested memory.

----------------------
-- Password Storage --
----------------------

-- | Generate an ASCII C-String string which includes:
--
-- * The result of a memory-hard, CPU-intensive hash function applied to the password;
-- * The automatically generated salt used for the previous computation;
-- * The other parameters required to verify the password: opslimit and memlimit.
--
-- /See also:/ [crypto_pwhash_scryptsalsa208sha256_str()](https://doc.libsodium.org/advanced/scrypt#password-storage)
--
-- @since 0.0.1.0
foreign import capi "sodium.h crypto_pwhash_scryptsalsa208sha256_str"
  cryptoPWHashScryptSalsa2018SHA256Str
    :: Ptr CChar
    -- ^ A pointer to the buffer receiving the string.
    -> Ptr CChar
    -- ^ The password
    -> CULLong
    -- ^ Password length
    -> CULLong
    -- ^ /opslimit:/ The maximum amount of computations to perform.
    -- The 'cryptoPWHashScryptSalsa2018SHA256OpsLimitInteractive' constant
    -- is a safe baseline value to use.
    -> CSize
    -- ^ /memlimit:/ The maximum amount of RAM in bytes that the function will use.
    -- The 'cryptoPWHashScryptSalsa2018SHA256MemLimitInteractive' constant
    -- is a safe baseline value to use.
    -> IO CInt
    -- ^ Returns 0 on success, -1 on error.

-- | Verify that the password verification string is valid for the associated password.
--
-- /See also:/ [crypto_pwhash_scryptsalsa208sha256_str_verify()](https://doc.libsodium.org/advanced/scrypt#password-storage)
--
-- @since 0.0.1.0
foreign import capi "sodium.h crypto_pwhash_scryptsalsa208sha256_str_verify"
  cryptoPWHashScryptSalsa2018SHA256StrVerify
    :: Ptr CChar
    -- ^ The password verification C-string, of size 'cryptoPWHashScryptSalsa2018SHA256StrBytes' bytes.
    -> Ptr CChar
    -- ^ The password.
    -> CULLong
    -- ^ The password length.
    -> IO CInt
    -- ^ Returns 0 on success, -1 on password verification failure.

---------------
-- Constants --
---------------

-- | Minimum size of the computed key.
--
-- @since 0.0.1.0
foreign import capi "sodium.h value crypto_pwhash_scryptsalsa208sha256_BYTES_MIN"
  cryptoPWHashScryptSalsa2018SHA256BytesMin :: CSize

-- | Maximum size of the computed key (~127GB).
--
-- @since 0.0.1.0
foreign import capi "sodium.h value crypto_pwhash_scryptsalsa208sha256_BYTES_MAX"
  cryptoPWHashScryptSalsa2018SHA256BytesMax :: CSize

-- | Maximum size of the password.
--
-- @since 0.0.1.0
foreign import capi "sodium.h value crypto_pwhash_scryptsalsa208sha256_PASSWD_MIN"
  cryptoPWHashScryptSalsa2018SHA256PasswdMin :: CSize

-- | Maximum size of the password/
--
-- @since 0.0.1.0
foreign import capi "sodium.h value crypto_pwhash_scryptsalsa208sha256_PASSWD_MAX"
  cryptoPWHashScryptSalsa2018SHA256PasswdMax :: CSize

-- | Length of the salt used by 'cryptoPWHashScryptSalsa2018SHA256'.
-- The easiest way to get a salt is to use 'LibSodium.Bindings.Random.randombytesBuf'.
--
-- @since 0.0.1.0
foreign import capi "sodium.h value crypto_pwhash_scryptsalsa208sha256_SALTBYTES"
  cryptoPWHashScryptSalsa2018SHA256SaltBytes :: CSize

-- | Length of the buffer receiving the string when using
-- 'cryptoPWHashScryptSalsa2018SHA256Str'.
--
-- @since 0.0.1.0
foreign import capi "sodium.h value crypto_pwhash_scryptsalsa208sha256_STRBYTES"
  cryptoPWHashScryptSalsa2018SHA256StrBytes :: CSize

-- | The string prefix that is prepended to the computed keys.
--
-- @since 0.0.1.0
foreign import capi "sodium.h value crypto_pwhash_scryptsalsa208sha256_STRPREFIX"
  cryptoPWHashScryptSalsa2018SHA256StrPrefix :: Ptr CChar

-- | The minimum amount of operations during the computation process
--
-- @since 0.0.1.0
foreign import capi "sodium.h value crypto_pwhash_scryptsalsa208sha256_OPSLIMIT_MIN"
  cryptoPWHashScryptSalsa2018SHA256OpsLimitMin :: CSize

-- | The maximum amount of operations during the computation process
--
-- @since 0.0.1.0
foreign import capi "sodium.h value crypto_pwhash_scryptsalsa208sha256_OPSLIMIT_MAX"
  cryptoPWHashScryptSalsa2018SHA256OpsLimitMax :: CSize

-- | The minimum amount of memory during the computation process
--
-- @since 0.0.1.0
foreign import capi "sodium.h value crypto_pwhash_scryptsalsa208sha256_MEMLIMIT_MIN"
  cryptoPWHashScryptSalsa2018SHA256MemLimitMin :: CSize

-- | The maximum amount of memory during the computation process
--
-- @since 0.0.1.0
foreign import capi "sodium.h value crypto_pwhash_scryptsalsa208sha256_MEMLIMIT_MAX"
  cryptoPWHashScryptSalsa2018SHA256MemLimitMax :: CSize

-- | The amount of operations most suitable for an interactive usage.
--
-- @since 0.0.1.0
foreign import capi "sodium.h value crypto_pwhash_scryptsalsa208sha256_OPSLIMIT_INTERACTIVE"
  cryptoPWHashScryptSalsa2018SHA256OpsLimitInteractive :: CSize

-- | The amount of memory most suitable for an interactive usage.
--
-- @since 0.0.1.0
foreign import capi "sodium.h value crypto_pwhash_scryptsalsa208sha256_MEMLIMIT_INTERACTIVE"
  cryptoPWHashScryptSalsa2018SHA256MemLimitInteractive :: CSize

-- | The amount of operations most suitable for for highly sensitive data.
--
-- ⚠  using the sensitive parameters can take up to 2 seconds on a 2.8GHz Core i7 CPU
-- and require up to 1GiB of dedicated RAM.
--
-- | @since 0.0.1.0
foreign import capi "sodium.h value crypto_pwhash_scryptsalsa208sha256_OPSLIMIT_SENSITIVE"
  cryptoPWHashScryptSalsa2018SHA256OpsLimitSensitive :: CSize

-- | The amount of memory most suitable for for highly sensitive data.
--
-- ⚠  using the sensitive parameters can take up to 2 seconds on a 2.8GHz Core i7 CPU
-- and require up to 1GiB of dedicated RAM.
--
-- @since 0.0.1.0
foreign import capi "sodium.h value crypto_pwhash_scryptsalsa208sha256_MEMLIMIT_SENSITIVE"
  cryptoPWHashScryptSalsa2018SHA256MemLimitSensitive :: CSize
