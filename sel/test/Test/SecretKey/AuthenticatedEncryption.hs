{-# LANGUAGE OverloadedStrings #-}

module Test.SecretKey.AuthenticatedEncryption where

import Sel.SecretKey.AuthenticatedEncryption
import Test.Tasty
import Test.Tasty.HUnit

spec :: TestTree
spec =
  testGroup
    "Secret Key Authenticated Encryption tests"
    [ testCase "Encrypt a message with a secret key and a nonce" testEncryptMessage
    ]

testEncryptMessage :: Assertion
testEncryptMessage = do
  secretKey <- newSecretKey
  nonce <- newNonce
  encryptedMessage <- encrypt "hello hello" secretKey nonce
  let result = decrypt encryptedMessage secretKey nonce
  assertEqual
    "Message is well-opened with the correct key and nonce"
    (Just "hello hello")
    result
