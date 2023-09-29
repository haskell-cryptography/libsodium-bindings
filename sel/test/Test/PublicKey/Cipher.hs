{-# LANGUAGE OverloadedStrings #-}

module Test.PublicKey.Cipher where

import Sel.PublicKey.Cipher
import Test.Tasty
import Test.Tasty.HUnit
import TestUtils

spec :: TestTree
spec =
  testGroup
    "Public Key Cipher tests"
    [ testCase "Encrypt a message with public-key encryption" testEncryptMessage
    , testCase "Round-trip nonce serialisation" testNonceSerdeRoundtrip
    , testCase "Round-trip keys serialisation" testKeysSerdeRoundtrip
    , testCase "Round-trip cipher text serialisation" testCipherTextSerdeRoundtrip
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
  let hexNonce = nonceToHexByteString nonce
  nonce2 <- assertRight $ nonceFromHexByteString hexNonce
  assertEqual "Roundtripping nonce serialisation" nonce nonce2

testKeysSerdeRoundtrip :: Assertion
testKeysSerdeRoundtrip = do
  (pk1, sk1) <- newKeyPair
  let hexPk = publicKeyToHexByteString pk1
  let hexSk = unsafeSecretKeyToHexByteString sk1
  (pk2, sk2) <- assertRight $ keyPairFromHexByteStrings hexPk hexSk
  assertEqual "Roundtripping keys serialisation" (pk1, sk1) (pk2, sk2)

testCipherTextSerdeRoundtrip :: Assertion
testCipherTextSerdeRoundtrip = do
  (publicKey, secretKey) <- newKeyPair
  (_, cipherText) <- encrypt "hello hello" publicKey secretKey
  let hexCipherText = cipherTextToHexByteString cipherText
  cipherText2 <- assertRight $ cipherTextFromHexByteString hexCipherText
  assertEqual "Roundtripping cipher text serialisation" cipherText cipherText2
