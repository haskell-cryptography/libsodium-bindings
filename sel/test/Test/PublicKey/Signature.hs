{-# LANGUAGE OverloadedStrings #-}

module Test.PublicKey.Signature where

import Sel.PublicKey.Signature
import Test.Tasty
import Test.Tasty.HUnit
import TestUtils

spec :: TestTree
spec =
  testGroup
    "Signing tests"
    [ testCase "Sign a message with a public key and decrypt it with a secret key" testSignMessage
    , testCase "Extract the public key from a secret key" testExtractPublicKey
    , testCase "Round-trip secret key serialisation" testSecretKeySerdeRoundtrip
    , testCase "Round-trip public key serialisation" testPublicKeySerdeRoundtrip
    ]

testSecretKeySerdeRoundtrip :: Assertion
testSecretKeySerdeRoundtrip = do
  (_, secretKey) <- generateKeyPair

  let secretKeyByteString = unsafeSecretKeyToHexByteString secretKey
  reconstructedSecretKey <- assertRight $ secretKeyFromHexByteString secretKeyByteString
  assertEqual
    "Secret key cannot be read from hex bytestring"
    secretKey
    reconstructedSecretKey

testPublicKeySerdeRoundtrip :: Assertion
testPublicKeySerdeRoundtrip = do
  (publicKey, _) <- generateKeyPair

  let publicKeyByteString = publicKeyToHexByteString publicKey
  reconstructedPublicKey <- assertRight $ publicKeyFromHexByteString publicKeyByteString
  assertEqual
    "Public key cannot be read from hex bytestring"
    publicKey
    reconstructedPublicKey

testSignMessage :: Assertion
testSignMessage = do
  (publicKey, secretKey) <- generateKeyPair
  signedMessage <- signMessage "hello hello" secretKey
  let result = openMessage signedMessage publicKey
  assertEqual
    "Message is well-opened with the correct key"
    (Just "hello hello")
    result

testExtractPublicKey :: Assertion
testExtractPublicKey = do
  (publicKey, secretKey) <- generateKeyPair
  let extractedPublicKey' = publicKeyFromSecretKey secretKey
  assertEqual
    "Public key extracted from Secret Key is not correct"
    publicKey
    extractedPublicKey'
