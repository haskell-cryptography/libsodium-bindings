{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE OverloadedStrings #-}
module Test.GenericHashing where

import Test.Tasty
import Test.Tasty.HUnit
import Foreign hiding (void)
import Control.Monad (void)
import Foreign.C
import qualified Data.ByteString.Internal as BS
import Data.ByteString (ByteString)
import LibSodium.Bindings.GenericHashing (cryptoGenericHash, cryptoGenericHashBytes, cryptoGenericHashKeyBytes)

spec :: TestTree
spec =
  testGroup
    "Generic hashing tests"
    [ testCase "cryptoGenericHash without key" testCryptoGenericHashWithoutKey
    ,  testCase "cryptoGenericHash with key" testCryptoGenericHashWithKey
    ]

testCryptoGenericHashWithoutKey :: Assertion
testCryptoGenericHashWithoutKey =
  withCStringLen "test test" $ \(cString, cstringLength) ->
  allocaBytes (fromIntegral cryptoGenericHashBytes) $ \outPtr -> do
    void $ cryptoGenericHash
      outPtr
      cryptoGenericHashBytes
      (castPtr cString :: Ptr CUChar)
      (fromIntegral cstringLength)
      nullPtr
      0
    out <- peekCString (castPtr outPtr)
    assertEqual "Hashed test string is consistent without key"
                "\DEL=\ETB\SOp\ETBd=\STXBLzL\SOHl2\CAN\DELQ"
                out

testCryptoGenericHashWithKey :: Assertion
testCryptoGenericHashWithKey =
  let key = "af7d1575690407317bf93723a8d1dca5"
      msg = "Test Test" :: String
      keyLength = cryptoGenericHashKeyBytes
  in
    withCStringLen msg $ \(cString, cstringLength) ->
    allocaBytes (fromIntegral cryptoGenericHashBytes) $ \outPtr ->
    withByteString key $ \keyPtr -> do
      void $ cryptoGenericHash
        outPtr
        cryptoGenericHashBytes
        (castPtr cString :: Ptr CUChar)
        (fromIntegral cstringLength)
        keyPtr
        keyLength
      out <- peekCString (castPtr outPtr)
      assertEqual "Hashed test string is consistent without key"
                  "<|1e$\SO3\888\GSsrs\15158\ESC4"
                  out

withByteString :: ByteString -> (Ptr a -> IO b) -> IO b
withByteString (BS.PS fptr off _) f = withForeignPtr fptr $ \ptr -> f $! (ptr `plusPtr` off)
