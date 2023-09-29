{-# LANGUAGE OverloadedStrings #-}

module Test.PublicKey.Cipher where

import Sel.PublicKey.Cipher
import Test.Tasty
import Test.Tasty.HUnit
import TestUtils (assertRight)

spec :: TestTree
spec =
  testGroup
    "Public Key Cipher tests"
    [ testCase "Encrypt a message with public-key encryption" testEncryptMessage
    , testCase "Round-trip nonce serialisation" testNonceSerdeRoundtrip
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

testNonceSerdeRoundtrip :: Assertion
testNonceSerdeRoundtrip = do
  (publicKey, secretKey) <- newKeyPair
  (nonce, _) <- encrypt "hello hello" publicKey secretKey
  nonce2 <- assertRight $ nonceFromHexByteString . nonceToHexByteString $ nonce
  assertEqual "Roundtripping" nonce nonce2
