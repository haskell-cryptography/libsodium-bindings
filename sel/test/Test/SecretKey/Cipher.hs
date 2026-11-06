{-# LANGUAGE OverloadedStrings #-}

module Test.SecretKey.Cipher where

import qualified Data.ByteString as BS
import Test.Tasty
import Test.Tasty.HUnit

import Sel.SecretKey.Cipher
import TestUtils (assertJust, assertRight)

spec :: TestTree
spec =
  testGroup
    "Secret Key Authenticated Encryption tests"
    [ testCase "Encrypt a message with a secret key and a nonce" testEncryptMessage
    , testCase "Round-trip nonce serialisation" testNonceSerdeRoundtrip
    , testCase "Round-trip secret key serialisation" testSecretKeySerdeRoundtrip
    , testCase "Round-trip ciphertext serialisation" testCiphertextSerdeRoundtrip
    , testCase "Round-trip secret key and nonce binary serialisation" testBinarySerdeRoundtrip
    , testCase "Wrong-length binary input is rejected" testBinaryWrongLength
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

testBinarySerdeRoundtrip :: Assertion
testBinarySerdeRoundtrip = do
  secretKey <- newSecretKey
  (nonce, _) <- encrypt "hello hello" secretKey
  secretKey2 <- assertJust (binaryToSecretKey (secretKeyToBinary secretKey))
  nonce2 <- assertJust (binaryToNonce (nonceToBinary nonce))
  assertEqual "Roundtripping secret key binary serialisation" secretKey secretKey2
  assertEqual "Roundtripping nonce binary serialisation" nonce nonce2

testBinaryWrongLength :: Assertion
testBinaryWrongLength = do
  assertEqual
    "A 16-byte input is rejected for a secret key"
    Nothing
    (binaryToSecretKey (BS.replicate 16 0))
  assertEqual
    "A 16-byte input is rejected for a nonce"
    Nothing
    (binaryToNonce (BS.replicate 16 0))
