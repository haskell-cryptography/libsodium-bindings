{-# LANGUAGE OverloadedStrings #-}

module Test.SecretKey.Cipher where

import Test.Tasty
import Test.Tasty.HUnit

import Sel.SecretKey.Cipher
import TestUtils (assertRight)

spec :: TestTree
spec =
  testGroup
    "Secret Key Authenticated Encryption tests"
    [ testCase "Encrypt a message with a secret key and a nonce" testEncryptMessage
    , testCase "Round-trip nonce serialisation" testNonceSerdeRoundtrip
    , testCase "Round-trip secret key serialisation" testSecretKeySerdeRoundtrip
    , testCase "Round-trip ciphertext serialisation" testCiphertextSerdeRoundtrip
    ]

testEncryptMessage :: Assertion
testEncryptMessage = do
  secretKey <- newSecretKey
  (nonce, encryptedMessage) <- encrypt "hello hello" secretKey
  let result = decrypt encryptedMessage secretKey nonce
  assertEqual
    "Message is well-opened with the correct key and nonce"
    (Just "hello hello")
    result

testNonceSerdeRoundtrip :: Assertion
testNonceSerdeRoundtrip = do
  secretKey <- newSecretKey
  (nonce, _) <- encrypt "hello hello" secretKey
  nonce2 <- assertRight $ nonceFromHexByteString . nonceToHexByteString $ nonce
  assertEqual "Roundtripping nonce" nonce nonce2

testSecretKeySerdeRoundtrip :: Assertion
testSecretKeySerdeRoundtrip = do
  secretKey <- newSecretKey
  secretKey2 <- assertRight $ secretKeyFromHexByteString . unsafeSecretKeyToHexByteString $ secretKey
  assertEqual "Roundtripping secret key" secretKey secretKey2

testCiphertextSerdeRoundtrip :: Assertion
testCiphertextSerdeRoundtrip = do
  secretKey <- newSecretKey
  (_, ciphertext) <- encrypt "" secretKey
  ciphertext2 <- assertRight $ ciphertextFromHexByteString . ciphertextToHexByteString $ ciphertext
  assertEqual "Roundtripping ciphertext" ciphertext ciphertext2
