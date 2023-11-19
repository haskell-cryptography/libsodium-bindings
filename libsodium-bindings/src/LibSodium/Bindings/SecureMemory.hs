{-# LANGUAGE CApiFFI #-}
{-# LANGUAGE ScopedTypeVariables #-}

-- |
--
-- Module: LibSodium.Bindings.SecureMemory
-- Description: Direct bindings to the libsodium secure memory functions
-- Copyright: (C) Hécate Moonlight 2022
-- License: BSD-3-Clause
-- Maintainer: The Haskell Cryptography Group
-- Portability: GHC only
module LibSodium.Bindings.SecureMemory
  ( -- ** Introduction
    -- $introduction

    -- ** Zeroing memory
    sodiumMemZero

    -- ** Locking memory
  , sodiumMlock
  , sodiumMunlock

    -- ** Allocating memory
  , sodiumMalloc
  , sodiumAllocArray
  , sodiumFree
  , finalizerSodiumFree
  )
where

import Data.Word (Word8)
import Foreign (FinalizerPtr, Ptr)
import Foreign.C.Types (CInt (CInt), CSize (CSize))

-- $introduction
-- This module provides bindings to the secure memory functions provided by Libsodium.
-- It is intended to be qualified on import:
--
-- > import qualified LibSodium.Bindings.SecureMemory as SecureMemory
--
-- It is recommended to disable swap partitions on machines processing sensitive
-- data or, as a second choice, use encrypted swap partitions.
--
-- For similar reasons, on Unix systems, one should also disable core dumps when
-- running crypto code outside a development environment.
-- This can be achieved using a shell built-in such as @ulimit@ or programmatically
-- using [@setResourceLimit@](https://hackage.haskell.org/package/unix/docs/System-Posix-Resource.html#v:setResourceLimit):
--
-- >>> setResourceLimit ResourceCoreFileSize (ResourceLimits 0 0)
--
-- On operating systems where this feature is implemented, kernel crash dumps
-- should also be disabled.
--
-- The 'sodiumMlock' function wraps @mlock(2)@ and
-- [@VirtualLock()@](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtuallock).
--
-- Note: Many systems place limits on the amount of memory that may be locked
-- by a process. Care should be taken to raise those limits (e.g. Unix ulimits)
-- where necessary.

-- | Overwrite the memory region starting at the pointer
-- address with zeros.
--
-- @memset()@ and hand-written code can be silently stripped out by
-- an optimizing compiler or the linker.
--
-- This function tries to effectively zero the amount of bytes starting
-- at the provided pointer, even if optimizations are being applied to the code.
--
-- /See:/ [sodium_memzero()](https://doc.libsodium.org/memory_management)
--
-- @since 0.0.1.0
foreign import capi "sodium.h sodium_memzero"
  sodiumMemZero
    :: Ptr Word8
    -- ^ Start pointer
    -> CSize
    -- ^ Length in bytes of the area to zero
    -> IO ()

-- | Lock a memory region starting at the pointer
-- address. This can help avoid swapping sensitive
-- data to disk.
--
-- /See:/ [sodium_mlock()](https://doc.libsodium.org/memory_management)
--
-- @since 0.0.1.0
foreign import capi "sodium.h sodium_mlock"
  sodiumMlock
    :: Ptr Word8
    -- ^ Start pointer
    -> CSize
    -- ^ Size of the memory region to lock
    -> IO CInt
    -- ^ Returns 0 on success, -1 if any system limit is reached.

-- | Unlock the memory region by overwriting it with zeros and and flagging the
-- pages as swappable again. Calling 'sodiumMemZero' prior to 'sodiumMunlock' is thus not required.
--
-- On systems where it is supported, 'sodiumMlock' also wraps @madvise(2)@ and advises the kernel not to include the locked memory in core dumps. The 'sodiumMunlock'
-- function also undoes this additional protection.
--
-- /See:/ [sodium_munlock()](https://doc.libsodium.org/memory_management)
--
-- @since 0.0.1.0
foreign import capi "sodium.h sodium_munlock"
  sodiumMunlock
    :: Ptr Word8
    -- ^ Start pointer
    -> CSize
    -- ^ Size of the memory region to unlock
    -> IO CInt

-- | This function takes an amount (called @size@) and returns a pointer from which
-- exactly @size@ contiguous bytes of memory can be accessed. The pointer may be
-- 'Foreign.Ptr.nullPtr' and there may be an error when allocating memory,
-- through @errno@. Upon failure, @errno@ will be set to 'Foreign.C.Error.eNOMEM'
--
-- It is recommended that the caller use "Foreign.C.Error" to handle potential failure.
--
-- Moreover, 'LibSodium.Bindings.Main.sodiumInit' must be called before using this
-- function.
--
-- === Explanation
-- The allocated region is placed at the end of a page boundary,
-- immediately followed by a guard page (or an emulation,
-- if unsupported by the platform). As a result, accessing memory past the end of the
-- region will immediately terminate the application.
--
-- A canary is also placed right before the returned pointer. Modifications of this
-- canary are detected when trying to free the allocated region with 'sodiumFree'
-- and cause the application to immediately terminate.
--
-- If supported by the platform, an additional guard page is placed before this canary
-- to make it less likely for sensitive data to be accessible when reading past the end
-- of an unrelated region.
-- The allocated region is filled with 0xdb bytes to help catch bugs due to
-- uninitialized data.
--
-- In addition, @mlock(2)@ is called on the region to help avoid it being swapped to disk.
-- Note however that @mlock(2)@ may not be supported, may fail or may be a no-op,
-- in which case 'sodiumMalloc' will return the memory regardless, but it will not be
-- locked. If you specifically need to rely on memory locking, consider calling
-- 'sodiumMlock' and checking its return value.
--
-- On operating systems supporting @MAP_NOCORE@ or @MADV_DONTDUMP@, memory allocated this
-- way will also not be part of core dumps.
-- The returned address will not be aligned if the allocation size is not a multiple
-- of the required alignment.
-- For this reason, 'sodiumMalloc' should not be used with packed or variable-length
-- structures unless the size given to 'sodiumMalloc' is rounded up to ensure proper
-- alignment.
--
-- All the structures used by libsodium can safely be allocated using
-- 'sodiumMalloc'.
--
-- Allocating 0 bytes is a valid operation. It returns a pointer that can be
-- successfully passed to 'sodiumFree'.
--
-- ⚠️  This is not a general-purpose allocation function, and requires 3 or 4 extra
-- pages of virtual memory. Since it is very expensive, do not use it to allocate
-- every-day memory.
--
-- /See:/ [sodium_malloc()](https://doc.libsodium.org/memory_management)
--
-- @since 0.0.1.0
foreign import capi "sodium.h sodium_malloc"
  sodiumMalloc
    :: forall a
     . CSize
    -- ^ Amount of memory to allocate
    -> IO (Ptr a)

-- | This function takes an amount of objects and the size of each object, and
-- returns a pointer from which this amount of objects that are of the specified
-- size each can be accessed.
--
-- It provides the same guarantees as 'sodiumMalloc' but also protects against
-- arithmetic overflows when @count * size@ exceeds @SIZE_MAX@.
--
-- /See:/ [sodium_allocarray()](https://doc.libsodium.org/memory_management)
--
-- @since 0.0.1.0
foreign import capi "sodium.h sodium_allocarray"
  sodiumAllocArray
    :: forall a
     . CSize
    -- ^ Amount of objects
    -> CSize
    -- ^ Size of each objects
    -> IO (Ptr a)

-- | Unlock and deallocate memory allocated using 'sodiumMalloc' or 'sodiumAllocArray'.
--
-- The memory region is filled with zeros before the deallocation.
--
-- /See:/ [sodium_free()](https://doc.libsodium.org/memory_management)
--
-- @since 0.0.1.0
foreign import capi "sodium.h sodium_free"
  sodiumFree
    :: forall a
     . Ptr a
    -> IO ()

-- | Function pointer to use as 'Foreign.ForeignPtr' finalizer for sodium-allocated memory.
--
-- The memory region is filled with zeros before the deallocation.
--
-- /See:/ [sodium_free()](https://doc.libsodium.org/memory_management)
--
-- @since 0.0.1.0
foreign import capi "sodium.h &sodium_free"
  finalizerSodiumFree
    :: forall a
     . FinalizerPtr a
