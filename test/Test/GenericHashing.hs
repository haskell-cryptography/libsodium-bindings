{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE OverloadedStrings #-}
module Test.GenericHashing where

import Test.Tasty
import Test.Tasty.HUnit
import qualified Data.ByteString as BS
import Foreign hiding (void)
import Control.Monad (void)
import Foreign.C
import LibSodium.Bindings.GenericHashing (cryptoGenericHash, cryptoGenericHashBytes)
import Data.ByteString (ByteString)

useByteString :: ByteString -> ((Ptr a, CSize) -> IO b) -> IO b
useByteString bs f =
  BS.useAsCStringLen bs $ \(b, l) ->
    f (castPtr b, fromIntegral l)

spec :: TestTree
spec =
  testGroup
    "Generic hashing tests"
    [ testCase "cryptoGenericHash" testCryptoGenericHash
    ]

testCryptoGenericHash :: Assertion
testCryptoGenericHash =
  withCStringLen "test test" $ \(cString, cstringLength) ->
  allocaBytes (sizeOf (undefined :: CUChar)) $ \outPtr -> do
    void $ cryptoGenericHash
      outPtr
      cryptoGenericHashBytes
      (castPtr cString :: Ptr CUChar)
      (fromIntegral cstringLength)
      nullPtr
      0
    out <- peekCString (castPtr outPtr)
    assertEqual "Hashed test string is consistent with key"
                "\DEL=\ETB\SOp\ETB\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL o\1186$\DEL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL"
                out
