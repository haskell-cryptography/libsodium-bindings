{-# LANGUAGE OverloadedStrings #-}

module Test.PublicKey.Cipher where

import Sel.PublicKey.Cipher
import Test.Tasty
import Test.Tasty.HUnit

spec :: TestTree
spec =
  testGroup
    "Public Key Cipher tests"
    [ testCase "Encrypt a message with public-key encryption" testEncryptMessage
    ]

testEncryptMessage :: Assertion
testEncryptMessage = do
  (senderPublicKey, senderSecretKey) <- newKeyPair

  (recipientPublicKey, recipientSecretKey) <- newKeyPair
  (nonce, encryptedMessage) <- encrypt "hello hello" recipientPublicKey senderSecretKey
  let result = decrypt encryptedMessage senderPublicKey recipientSecretKey nonce
  assertEqual
    "Message is well-opened with the correct key and nonce"
    (Just "hello hello")
    result
