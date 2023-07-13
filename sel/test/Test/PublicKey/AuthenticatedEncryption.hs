{-# LANGUAGE OverloadedStrings #-}

module Test.PublicKey.AuthenticatedEncryption where

import Sel.PublicKey.AuthenticatedEncryption
import Test.Tasty
import Test.Tasty.HUnit

spec :: TestTree
spec =
  testGroup
    "Public Key Authenticated Encryption tests"
    [ testCase "Encrypt a message with public-key encryption" testEncryptMessage
    ]

testEncryptMessage :: Assertion
testEncryptMessage = do
  (senderSecretKey, senderPublicKey) <- newKeyPair
  (recipientSecretKey, recipientPublicKey) <- newKeyPair
  (nonce, encryptedMessage) <- encrypt "hello hello" senderSecretKey recipientPublicKey
  let result = decrypt encryptedMessage recipientSecretKey senderPublicKey nonce
  assertEqual
    "Message is well-opened with the correct key and nonce"
    (Just "hello hello")
    result
