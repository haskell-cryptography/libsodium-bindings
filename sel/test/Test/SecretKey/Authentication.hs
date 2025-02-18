{-# LANGUAGE OverloadedStrings #-}

module Test.SecretKey.Authentication where

import Test.Tasty
import Test.Tasty.HUnit

import Sel.SecretKey.Authentication
import TestUtils (assertRight)

spec :: TestTree
spec =
  testGroup
    "Secret Key Authentication tests"
    [ testCase "Authenticate a message with a fixed secret key" testAuthenticateMessage
    , testCase "Round-trip auth key serialisation" testAuthKeySerdeRoundtrip
    , testCase "Round-trip auth tag serialisation" testAuthTagSerdeRoundtrip
    ]

testAuthenticateMessage :: Assertion
testAuthenticateMessage = do
  key <- newAuthenticationKey
  let tag = authenticate "hello, world" key
  assertBool
    "Tag verified"
    (verify tag key "hello, world")

testAuthKeySerdeRoundtrip :: Assertion
testAuthKeySerdeRoundtrip = do
  expectedKey <- newAuthenticationKey
  let hexKey = unsafeAuthenticationKeyToHexByteString expectedKey
  actualKey <- assertRight $ authenticationKeyFromHexByteString hexKey
  assertEqual
    "Key is expected"
    expectedKey
    actualKey

testAuthTagSerdeRoundtrip :: Assertion
testAuthTagSerdeRoundtrip = do
  key <- newAuthenticationKey
  let expectedTag = authenticate "hello, world" key
      hexTag = authenticationTagToHexByteString expectedTag
  actualTag <- assertRight $ authenticationTagFromHexByteString hexTag
  assertEqual
    "Tag is expected"
    expectedTag
    actualTag
