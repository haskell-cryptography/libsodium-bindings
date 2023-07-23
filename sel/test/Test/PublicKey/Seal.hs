{-# LANGUAGE OverloadedStrings #-}

module Test.PublicKey.Seal where

import Sel.PublicKey.Cipher
import Sel.PublicKey.Seal
import Test.Tasty
import Test.Tasty.HUnit

spec :: TestTree
spec =
  testGroup
    "Public Key Anonymous Sealing tests"
    [ testCase "Encrypt an anonymous message with public-key encryption" testEncryptMessage
    ]

testEncryptMessage :: Assertion
testEncryptMessage = do
  (recipientPublicKey, recipientSecretKey) <- newKeyPair
  encryptedMessage <- seal "hello hello" recipientPublicKey
  let result = open encryptedMessage recipientPublicKey recipientSecretKey
  assertEqual
    "Message is well-opened"
    (Just "hello hello")
    result
