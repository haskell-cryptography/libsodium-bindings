{-# LANGUAGE CApiFFI #-}

module HashingTests where

import Cryptography.Sodium.Bindings.Hashing
import Foreign (Ptr, allocaBytes, peekArray0)
import qualified Foreign as C
import Foreign.C (CInt (..), CSize (..), CUChar)
import qualified Foreign.C.String as C
import Test.Tasty
import Test.Tasty.HUnit

spec :: TestTree
spec =
  testGroup
    "Hashing tests"
    [ testCase "Test hashing a single message with a key" testHashingWithAKey,
      testCase "Test hashing a single message with no key" testHashingWithNoKey
    ]

testHashingWithAKey :: Assertion
testHashingWithAKey = do
  allocaBytes (fromIntegral cryptoGenericHashBytes) $ \outPtr1 ->
    allocaBytes (fromIntegral cryptoGenericHashBytes) $ \outPtr2 ->
      allocaBytes (fromIntegral cryptoGenericHashBytes) $ \keyPtr -> do
        let outParameter1 = C.castPtr outPtr1 :: Ptr CUChar
        let outLen1 = cryptoGenericHashBytes

        let outParameter2 = C.castPtr outPtr2 :: Ptr CUChar
        let outLen2 = cryptoGenericHashBytes

        let messageString = "Hi Bob, I'm in your system now! ;)"
        (cString, stringSize) <- C.newCStringLen messageString
        let inLen = fromIntegral stringSize
        let inParameter = C.castPtr cString :: Ptr CUChar

        let keyParameter = C.castPtr keyPtr :: Ptr CUChar
        let keyLen = cryptoGenericHashKeyBytes
        cryptoGenericHashKeyGen keyParameter

        cryptoGenericHash
          outParameter1
          outLen1
          inParameter
          inLen
          keyParameter
          keyLen

        cryptoGenericHash
          outParameter2
          outLen2
          inParameter
          inLen
          keyParameter
          keyLen

        result <- memcmp outParameter1 outParameter2 cryptoGenericHashBytes
        assertBool "The result is expected" (result == 0)

testHashingWithNoKey :: Assertion
testHashingWithNoKey = do
  allocaBytes (fromIntegral cryptoGenericHashBytes) $ \outPtr ->
    allocaBytes (fromIntegral cryptoGenericHashBytes) $ \keyPtr -> do
      let outParameter = C.castPtr outPtr :: Ptr CUChar
      let outLen = cryptoGenericHashBytes

      let messageString = "Hi Bob, I'm in your system now! ;)"
      (cString, stringSize) <- C.newCStringLen messageString
      let inLen = fromIntegral stringSize
      let inParameter = C.castPtr cString :: Ptr CUChar

      let keyParameter = C.castPtr keyPtr :: Ptr CUChar
      let keyLen = cryptoGenericHashKeyBytes

      cryptoGenericHash
        outParameter
        outLen
        inParameter
        inLen
        keyParameter
        keyLen

      result <- peekArray0 0x0 outParameter
      assertEqual
        "The result is expected"
        result
{- ORMOLU_DISABLE -}
        [ 0x86, 0x89, 0x62, 0x5A, 0x8B, 0x56, 0xFD, 0xB, 0x81, 0xBC, 0x35, 0x63, 0xAB,
          0xDC, 0x6C, 0x2D, 0x4C, 0xBC, 0xBA, 0x83, 0x12, 0x53, 0xFD, 0x6C, 0x21, 0x39,
          0xC1, 0x86, 0x29, 0x33, 0x54, 0x6B, 0x78, 0x78, 0x5C
        ]

foreign import capi "string.h memcmp"
  memcmp :: Ptr CUChar -> Ptr CUChar -> CSize -> IO CInt
