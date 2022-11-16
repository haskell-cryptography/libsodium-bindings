{-# LANGUAGE OverloadedStrings #-}

module Test.Signing where

import Sel.Signing
import Test.Tasty
import Test.Tasty.HUnit

spec :: TestTree
spec =
  testGroup
    "Signing tests"
    [ testCase "Sign a message with a public key and decrypt it with a secret key" testSignMessage
    ]

testSignMessage :: Assertion
testSignMessage = do
  (publicKey, secretKey) <- generateKeyPair
  signedMessage <- signMessage "hello hello" secretKey
  let result = openMessage signedMessage publicKey
  assertEqual
    "Message is well-opened with the correct key"
    (Just "hello hello")
    result
