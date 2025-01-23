{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ScopedTypeVariables #-}

module Test.Scrypt where

import Data.ByteString
import Test.Tasty
import Test.Tasty.HUnit

import Sel.Scrypt

spec :: TestTree
spec =
  testGroup
    "Scrypt tests"
    [ testCase "Hash Scrypt password" testHashScrypt
    , testCase "Verify Scrypt password" testVerifyScrypt
    ]

testHashScrypt :: Assertion
testHashScrypt = do
  let hash = "This is not a real hash." :: StrictByteString
  scryptHashPassword hash
  return ()

testVerifyScrypt :: Assertion
testVerifyScrypt = do
  let hash = "This is not a real hash." :: StrictByteString
  sh <- scryptHashPassword hash
  res <- scryptVerifyPassword hash sh
  assertBool "Verifier failed." res
