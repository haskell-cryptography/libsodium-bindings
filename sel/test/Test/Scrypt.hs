{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ScopedTypeVariables #-}

module Test.Scrypt where

import Data.ByteString
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
  let hash = "This is not a real hash." :: StrictByteString
  scryptStorePassword hash
  return ()

testVerifyScrypt :: Assertion
testVerifyScrypt = do
  let hash = "This is not a real hash." :: StrictByteString
  sh <- scryptStorePassword hash
  res <- scryptVerifyPassword hash sh
  assertBool "Verifier failed." res
