{-# LANGUAGE OverloadedStrings #-}

module Test.SecretKey.Cipher where

import Sel.SecretKey.Cipher
import Test.Tasty
import Test.Tasty.HUnit
import TestUtils (assertRight)

spec :: TestTree
spec =
  testGroup
    "Secret Key Authenticated Encryption tests"
    [ testCase "Encrypt a message with a secret key and a nonce" testEncryptMessage
    , testCase "Round-trip nonce serialisation" testNonceSerdeRoundtrip
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
  assertEqual "Roundtripping" nonce nonce2
