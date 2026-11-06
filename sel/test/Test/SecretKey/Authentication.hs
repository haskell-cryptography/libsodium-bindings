{-# LANGUAGE OverloadedStrings #-}

module Test.SecretKey.Authentication where

import qualified Data.ByteString as BS
import Test.Tasty
import Test.Tasty.HUnit

import Sel.SecretKey.Authentication
import TestUtils (assertJust, assertRight)

spec :: TestTree
spec =
  testGroup
    "Secret Key Authentication tests"
    [ testCase "Authenticate a message with a fixed secret key" testAuthenticateMessage
    , testCase "Round-trip auth key serialisation" testAuthKeySerdeRoundtrip
    , testCase "Round-trip auth tag serialisation" testAuthTagSerdeRoundtrip
    , testCase "Round-trip auth key and tag binary serialisation" testBinarySerdeRoundtrip
    , testCase "Wrong-length binary input is rejected" testBinaryWrongLength
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

testBinarySerdeRoundtrip :: Assertion
testBinarySerdeRoundtrip = do
  key <- newAuthenticationKey
  let expectedTag = authenticate "hello, world" key
  key2 <- assertJust (binaryToAuthenticationKey (authenticationKeyToBinary key))
  tag2 <- assertJust (binaryToAuthenticationTag (authenticationTagToBinary expectedTag))
  assertEqual "Key is expected" key key2
  assertEqual "Tag is expected" expectedTag tag2

testBinaryWrongLength :: Assertion
testBinaryWrongLength = do
  assertEqual
    "A 16-byte input is rejected for an authentication key"
    Nothing
    (binaryToAuthenticationKey (BS.replicate 16 0))
  assertEqual
    "A 16-byte input is rejected for an authentication tag"
    Nothing
    (binaryToAuthenticationTag (BS.replicate 16 0))
