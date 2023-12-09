{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ScopedTypeVariables #-}

module Test.Scrypt where

import Data.ByteString
import Data.ByteString.Char8 as BSC8
import Data.ByteString.Unsafe (unsafeUseAsCString)
import Foreign
import Foreign.C
import Foreign.Ptr
import Sel.Scrypt
import Test.Tasty
import Test.Tasty.HUnit

spec :: TestTree
spec =
  testGroup
    "Scrypt tests"
    [ testCase "Store Scrypt password" testStoreScrypt
    , testCase "Verify Scrypt password" testVerifyScrypt
    ]

testStoreScrypt :: Assertion
testStoreScrypt = do
  let hash = "This is not a real hash." :: String
  res <- scryptStorePassword (BSC8.pack hash)
  out <- withForeignPtr (unScryptHash res) $ \result -> peekCString (castPtr result)
  assertEqual
    "Test string has been stored correctly."
    hash
    out

testVerifyScrypt :: Assertion
testVerifyScrypt = do
  let key = " fdbabe1c9d3472007856e7190d01e9fe7c6ad7cbc8237830e77376634b3731622eaf30d92e22a3886ff109279d9830dac727afb94a83ee6d8360cbdfa2cc0640" :: StrictByteString
      pass = "70617373776f7264"
  sh <- unsafeUseAsCString key $ \ptr -> newForeignPtr_ ptr
  res <- scryptVerifyPassword pass (mkScryptHash sh)
  assertBool "Verifier failed." res
