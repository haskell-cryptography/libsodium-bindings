{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ScopedTypeVariables #-}

module Test.Hashing.Generic where

import Control.Monad (void)

-- import qualified Data.ByteString.Char8 as BS
import qualified Data.ByteString.Unsafe as BS
import Foreign hiding (void)
import Foreign.C
import LibSodium.Bindings.GenericHashing (cryptoGenericHash, cryptoGenericHashBytes)
import Sel.Hashing.Generic
import Test.Tasty
import Test.Tasty.HUnit

spec :: TestTree
spec =
  testGroup
    "Generic hashing tests"
    [ testCase "cryptoGenericHash without key" testCryptoGenericHashWithoutKey
    , testCase "cryptoGenericHash with key" testCryptoGenericHashWithKey
    ]

testCryptoGenericHashWithoutKey :: Assertion
testCryptoGenericHashWithoutKey = do
  expected <- hashToHexByteString <$> hashByteString Nothing "test test"
  assertEqual
    "Hashed test string is consistent without key"
    expected
    "7f3dc1170e7017a1643d84d102429c4c7aec4ca99c016c32af18af997fed51f1"

testCryptoGenericHashWithKey :: Assertion
testCryptoGenericHashWithKey =
  let key = "af7d1575690407317bf93723a8d1dca5"
      msg = "Test Test" :: String
   in withCStringLen msg $ \(cString, cstringLength) ->
        allocaBytes (fromIntegral cryptoGenericHashBytes) $ \outPtr ->
          BS.unsafeUseAsCStringLen key $ \(keyPtr, keyLength) -> do
            void $
              cryptoGenericHash
                outPtr
                cryptoGenericHashBytes
                (castPtr cString :: Ptr CUChar)
                (fromIntegral cstringLength)
                (castPtr keyPtr)
                (fromIntegral keyLength)
            out <- peekCStringLen (castPtr outPtr, cstringLength)
            assertEqual
              "Hashed test string is consistent with key"
              "<|1"
              out
