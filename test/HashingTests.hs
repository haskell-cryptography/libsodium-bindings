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
{- ORMOLU_DISABLE -}
        [ 195,47,89,204,211,6,152,105,25,132,237,165,254
        , 238,19,173,117,50,140,229,20,190,187,78,98,57
        , 250,225,213,20,48,166
        ]
        result

foreign import capi "string.h memcmp"
  memcmp :: Ptr CUChar -> Ptr CUChar -> CSize -> IO CInt
