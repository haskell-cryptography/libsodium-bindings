{-# LANGUAGE CApiFFI #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE Trustworthy #-}
{-# OPTIONS_GHC -Wno-unused-imports #-}

-- \| These are bindings to some of sodium's utils.h.
-- Included are Hex and Base64 encoding/decoding functions
-- along with a constant-time `memcmp` for handling secret data.

-- | Module: LibSodium.Bindings.Utils
-- Description: Helpers defined in utils.h
-- Copyright: (C) Seth Livy 2022
-- License: BSD-3-Clause
-- Maintainer: sethlivy@gmail.com
-- Stability: Stable
-- Portability: GHC only
module LibSodium.Bindings.Utils
  ( -- * Low-level binding
    sodiumMemcmp
  , sodiumBin2Hex
  , sodiumHex2Bin
  , sodiumBin2Base64
  , sodiumBase642Bin

    -- * Constants
  , sodiumBase64VariantOriginal
  , sodiumBase64VariantOriginalNoPadding
  , sodiumBase64VariantURLSafe
  , sodiumBase64VariantURLSafeNoPadding
  )
where

import Foreign (Ptr)
import Foreign.C (CChar (CChar), CInt (CInt), CSize (CSize), CUChar)
import Foreign.C.String

-- | Constant-time comparison function.
--
-- This function is not a lexicographic comparator and should be never
-- used for this purpose. It should only be used when comparing two pieces
-- of secret data, such as keys or authentication tags.
foreign import capi "sodium.h sodium_memcmp"
  sodiumMemcmp
    :: Ptr CUChar
    -- ^ First pointer to some secret data.
    -> Ptr CUChar
    -- ^ Second pointer to some secret data.
    -- Must be the same length as the first pointer.
    -> CSize
    -- ^ The length of bytes that pointed to by both previous arguments.
    -> IO CInt
    -- ^ 0 if successful, -1 on failure.

-- | Encode bytes to a hexidecimal string. Constant-time.
foreign import capi "sodium.h sodium_bin2hex"
  sodiumBin2Hex
    :: CString
    -- ^ `hex`, The output buffer.
    -> CSize
    -- ^ `hex_len`, The maximum number of bytes this function is allowed to write
    -- to the output buffer. Must be at least `bin_len * 2 + 1` bytes long.
    -> Ptr CUChar
    -- ^ `bin`, The input buffer.
    -> CSize
    -- ^ `bin_len`, The length of the input buffer.
    -> IO CString
    -- ^ The return string, terminated with a null byte.

-- | Decode a hexadecimal string to bytes. Constant-time.
foreign import capi "sodium.h sodium_hex2bin"
  sodiumHex2Bin
    :: Ptr CUChar
    -- ^ `bin`, The output buffer.
    -> CSize
    -- ^ `bin_maxlen`, The maximum length of the output buffer.
    -> CString
    -- ^ `hex`, The input string.
    -> CSize
    -- ^ `hex_len`, The length of the input.
    -> CString
    -- ^ `ignore`, a string of characters for the parser to skip.
    -- For example, the string ": " allows colons and spaces in the input.
    -- These characters will ignored and will not be present in the output.
    -> Ptr CSize
    -- ^ `bin_len`, The length of the output buffer.
    -> Ptr (Ptr CChar)
    -- ^ `hex_end`, A pointer to the end of the input string.
    -- If this isn't null, then it will be set to the first byte after the last
    -- valid parsed character.
    -> IO CInt
    -- ^ 0 if successful, -1 on failure. Common failures are if the string
    -- couldn't be fully parsed or if the parsed string is longer than the
    -- maximum amount of bytes allocated to store it.

-- | Encode bytes to a Base64 string. Constant-time.
foreign import capi "sodium.h sodium_bin2base64"
  sodiumBin2Base64
    :: CString
    -- ^ `b64`, The output buffer.
    -> CSize
    -- ^ `b64_maxlen`, The maximum length of the output buffer.
    -- Choosing a correct size is not straightforward and depends on
    -- the variant. The `sodium_base64_ENCODED_LEN(BIN_LEN, VARIANT)`
    -- macro computes the minimum amount of bytes needed to encode BIN_LEN
    -- bytes with a chosen VARIANT.
    -> Ptr CUChar
    -- ^ `bin`, The input buffer.
    -> CSize
    -- ^ `bin_len`, The length of the input buffer.
    -> CInt
    -- ^ `variant`, Which Base64 variant to use. None of the variants provide
    -- any encryption.
    -> IO CString
    -- ^ The returned Base64 string, terminated with a null byte.

foreign import capi "sodium.h sodium_base642bin"
  sodiumBase642Bin
    :: Ptr CUChar
    -- ^ `bin`, The output buffer.
    -> CSize
    -- ^ `bin_maxlen`, The maximum length of the output buffer.
    -> CString
    -- ^ `b64`, The input string.
    -> CSize
    -- ^ `b64_len`, The length of the input.
    -> CString
    -- ^ `ignore`, a string of characters for the parser to skip.
    -- For example, the string ": " allows colons and spaces in the input.
    -- These characters will ignored and will not be present in the output.
    -> Ptr CSize
    -- ^ `bin_len`, The length of the output buffer.
    -- This will always be at most `b64_len / 4 * 3` bytes long.
    -> Ptr (Ptr CChar)
    -- ^ `b64_end`, A pointer to the end of the input string.
    -- If this isn't null, then it will be set to the first byte after the last
    -- valid parsed character.
    -> CInt
    -- ^ `variant`, Which Base64 variant to use. None of the variants provide
    -- any encryption.
    -> IO CInt
    -- ^ 0 if successful, -1 on failure. Common failures are if the string
    -- couldn't be fully parsed or if the parsed string is longer than the
    -- maximum amount of bytes allocated to store it.

foreign import capi "sodium.h value sodium_base64_VARIANT_ORIGINAL"
  sodiumBase64VariantOriginal :: CInt

foreign import capi "sodium.h value sodium_base64_VARIANT_ORIGINAL_NO_PADDING"
  sodiumBase64VariantOriginalNoPadding :: CInt

foreign import capi "sodium.h value sodium_base64_VARIANT_URLSAFE"
  sodiumBase64VariantURLSafe :: CInt

foreign import capi "sodium.h value sodium_base64_VARIANT_URLSAFE_NO_PADDING"
  sodiumBase64VariantURLSafeNoPadding :: CInt
