{-# LANGUAGE CApiFFI #-}
{-|
  Module      : Cryptography.LibSodium.FFI
  Copyright   : © Input Ouput Global Ltd, 2016
                  cryptography-libsodium contributors
  License     : Apache-2.0
  Maintainer  : hecate@glitchbra.in
-}

module Cryptography.LibSodium.FFI
  ( -- * Initialization
    c_sodium_init
   -- * Memory management
   -- ** Zeroing Memory
  , c_sodium_memzero
   -- ** Guarded heap allocations
  , c_sodium_malloc
  , c_sodium_free
  , c_sodium_free_funptr
   -- * Hashing
   -- ** SHA-256
  , c_crypto_hash_sha256
  , c_crypto_hash_sha256_final
  , c_crypto_hash_sha256_init
  , c_crypto_hash_sha256_update
   -- ** Blake2b 256
  , c_crypto_generichash_blake2b
  , c_crypto_generichash_blake2b_final
  , c_crypto_generichash_blake2b_init
  , c_crypto_generichash_blake2b_update
   -- * Helpers
  , c_sodium_compare
  ) where

import Foreign.C.Types (CInt(..), CUChar(..), CULLong(..), CSize(..))
import Foreign.Ptr (FunPtr, Ptr)

import Cryptography.LibSodium.Hash.Types

#include <sodium.h>
#include <sodium/crypto_hash_sha256.h>
#include <sodium/crypto_hash_sha512.h>
#include <sodium/crypto_generichash_blake2b.h>

-------------------------------------------------------------------------------
-- Initialization
-------------------------------------------------------------------------------

-- | The sodium_init() function must then be called before any other function.
-- It is safe to call sodium_init() multiple times, or from different threads;
-- it will immediately return 1 without doing anything if the library had already been initialized.
--
-- @void sodium_init()@
--
-- <https://libsodium.gitbook.io/doc/usage>
--
-- @since 0.0.1.0
foreign import capi "sodium.h sodium_init"  c_sodium_init :: IO CInt

-------------------------------------------------------------------------------
-- Memory management
-------------------------------------------------------------------------------

-- | After use, sensitive data should be overwritten, but memset() and hand-written
-- code can be silently stripped out by an optimizing compiler or by the linker.
--
-- @void sodium_memzero(void * const pnt, const size_t len)@
--
-- <https://libsodium.gitbook.io/doc/memory_management#zeroing-memory>
--
-- @since 0.0.1.0
foreign import capi unsafe "sodium.h sodium_memzero" c_sodium_memzero :: Ptr a -> CSize -> IO ()

-- $guadedHeapAllocations
-- Sodium provides heap allocation functions for storing sensitive data.
-- These are not general-purpose allocation functions. In particular, they are slower
-- than @malloc()@ and friends, and they require 3 or 4 extra pages of virtual memory.
-- @sodium_init()@ has to be called before using any of the guarded heap allocation functions.

-- | The sodium_malloc() function returns a pointer from which exactly size contiguous bytes of memory can be accessed.
-- Like normal malloc, NULL may be returned and errno set if it is not possible to allocate enough memory.
-- The allocated region is placed at the end of a page boundary, immediately followed by a guard page.
-- As a result, accessing memory past the end of the region will immediately terminate the application.
-- A canary is also placed right before the returned pointer. Modifications of this canary are detected when trying
-- to free the allocated region with sodium_free(), and also cause the application to immediately terminate.
-- An additional guard page is placed before this canary to make it less likely for sensitive data to be accessible
-- when reading past the end of an unrelated region.
-- The allocated region is filled with 0xdb bytes in order to help catch bugs due to uninitialized data.
-- In addition, sodium_mlock() is called on the region to help avoid it being swapped to disk.
-- On operating systems supporting MAP_NOCORE or MADV_DONTDUMP, memory allocated this way will also not be part of core dumps.
-- The returned address will not be aligned if the allocation size is not a multiple of the required alignment.
-- For this reason, sodium_malloc() should not be used with packed or variable-length structures,
-- unless the size given to sodium_malloc() is rounded up in order to ensure proper alignment.
-- All the structures used by libsodium can safely be allocated using sodium_malloc().
-- Allocating 0 bytes is a valid operation. It returns a pointer that can be successfully passed to sodium_free().
--
-- @void *sodium_malloc(size_t size)@
--
-- <https://libsodium.gitbook.io/doc/memory_management>
foreign import capi unsafe "sodium.h sodium_malloc" c_sodium_malloc :: CSize -> IO (Ptr a)
--
-- | @void sodium_free(void *ptr)@
--
-- <https://libsodium.gitbook.io/doc/memory_management>
foreign import capi unsafe "sodium.h sodium_free" c_sodium_free :: Ptr a -> IO ()

-- | @void sodium_free(void *ptr)@
--
-- <https://libsodium.gitbook.io/doc/memory_management>
foreign import capi unsafe "sodium.h &sodium_free" c_sodium_free_funptr :: FunPtr (Ptr a -> IO ())

-------------------------------------------------------------------------------
-- Hashing: Blake2b
-------------------------------------------------------------------------------

-- | @int crypto_generichash_blake2b(unsigned char *out, size_t outlen, const unsigned char *in, unsigned long long inlen, const unsigned char *key, size_t keylen)@
--
-- <https://libsodium.gitbook.io/doc/hashing/generic_hashing>
foreign import capi unsafe "sodium.h crypto_generichash_blake2b" c_crypto_generichash_blake2b
    :: Ptr out
    -> CSize
    -> Ptr CUChar
    -> CULLong
    -> Ptr key
    -> CSize
    -> IO CInt

-- | @int crypto_generichash_blake2b_init(crypto_generichash_blake2b_state *state, const unsigned char *key, const size_t keylen, const size_t outlen)@
foreign import capi unsafe "sodium.h crypto_generichash_blake2b_init" c_crypto_generichash_blake2b_init
  :: Ptr Blake2bState
  -> Ptr key
  -> CSize
  -> CSize
  -> IO CInt

-- | @int crypto_generichash_blake2b_update(crypto_generichash_blake2b_state *state, const unsigned char *in, unsigned long long inlen)@
foreign import capi unsafe "sodium.h crypto_generichash_blake2b_update" c_crypto_generichash_blake2b_update
  :: Ptr Blake2bState
  -> Ptr CUChar
  -> CULLong
  -> IO CInt

-- | @int crypto_generichash_blake2b_final(crypto_generichash_blake2b_state *state, unsigned char *out, const size_t outlen)@
foreign import capi unsafe "sodium.h crypto_generichash_blake2b_final" c_crypto_generichash_blake2b_final :: Ptr Blake2bState -> Ptr out -> CSize -> IO CInt

-------------------------------------------------------------------------------
-- Hashing: SHA256
-------------------------------------------------------------------------------

-- | @int crypto_hash_sha256(unsigned char *out, const unsigned char *in, unsigned long long inlen);@
--
-- <https://libsodium.gitbook.io/doc/advanced/sha-2_hash_function>
foreign import capi unsafe "sodium.h crypto_hash_sha256" c_crypto_hash_sha256 :: Ptr CUChar -> Ptr CUChar -> CULLong -> IO Int

-- | @int crypto_hash_sha256_init(crypto_hash_sha256_state *state);@
foreign import capi unsafe "sodium.h crypto_hash_sha256_init" c_crypto_hash_sha256_init :: Ptr Blake2bState -> IO Int

-- | @int crypto_hash_sha256_update(crypto_hash_sha256_state *state, const unsigned char *in, unsigned long long inlen);@
foreign import capi unsafe "sodium.h crypto_hash_sha256_update" c_crypto_hash_sha256_update :: Ptr Blake2bState -> Ptr CUChar -> CULLong -> IO Int

-- | @int crypto_hash_sha256_final(crypto_hash_sha256_state *state, unsigned char *out);@
foreign import capi unsafe "sodium.h crypto_hash_sha256_final" c_crypto_hash_sha256_final :: Ptr Blake2bState -> Ptr CUChar -> IO Int

------------------------------------------------------------------------------------------------
-- Helpers
-------------------------------------------------------------------------------

-- | @int sodium_compare(const void * const b1_, const void * const b2_, size_t len)@
--
-- <https://libsodium.gitbook.io/doc/helpers#comparing-large-numbers>
foreign import capi unsafe "sodium.h sodium_compare" c_sodium_compare :: Ptr a -> Ptr a -> CSize -> IO CInt
