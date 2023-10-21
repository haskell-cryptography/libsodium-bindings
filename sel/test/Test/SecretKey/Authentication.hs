{-# LANGUAGE OverloadedStrings #-}

module Test.SecretKey.Authentication where

import Sel.SecretKey.Authentication
import Test.Tasty
import Test.Tasty.HUnit
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
  key <- assertRight $ authenticationKeyFromHexByteString "a84b24baf25e5012faefaa7613645983f0c2ec42a7edf7de30e79d97e0ad8276"
  tag <- authenticate "hello, world" key
  assertEqual
    "Tag is expected"
    "6bf8ade5374886be411ecfa7da9897766e4058650756a4af8ca2b93c47176d17"
    (authenticationTagToHexByteString tag)

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
  expectedTag <- authenticate "hello, world" key
  let hexTag = authenticationTagToHexByteString expectedTag
  actualTag <- assertRight $ authenticationTagFromHexByteString hexTag
  assertEqual
    "Tag is expected"
    expectedTag
    actualTag
