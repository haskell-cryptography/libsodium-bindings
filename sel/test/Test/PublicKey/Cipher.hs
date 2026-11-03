{-# LANGUAGE OverloadedStrings #-}

module Test.PublicKey.Cipher where

import qualified Data.ByteString as BS
import Test.Tasty
import Test.Tasty.HUnit

import Sel.PublicKey.Cipher
import TestUtils

spec :: TestTree
spec =
  testGroup
    "Public Key Cipher tests"
    [ testCase "Encrypt a message with public-key encryption" testEncryptMessage
    , testCase "Round-trip nonce serialisation" testNonceSerdeRoundtrip
    , testCase "Round-trip keys serialisation" testKeysSerdeRoundtrip
    , testCase "Round-trip cipher text serialisation" testCiphertextSerdeRoundtrip
    , testCase "Round-trip keys and nonce binary serialisation" testBinarySerdeRoundtrip
    , testCase "Wrong-length binary input is rejected" testBinaryWrongLength
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

testCiphertextSerdeRoundtrip :: Assertion
testCiphertextSerdeRoundtrip = do
  (publicKey, secretKey) <- newKeyPair
  (_, ciphertext) <- encrypt "hello hello" publicKey secretKey
  let hexCiphertext = ciphertextToHexByteString ciphertext
  ciphertext2 <- assertRight $ ciphertextFromHexByteString hexCiphertext
  assertEqual "Roundtripping cipher text serialisation" ciphertext ciphertext2

testBinarySerdeRoundtrip :: Assertion
testBinarySerdeRoundtrip = do
  (publicKey, secretKey) <- newKeyPair
  (nonce, _) <- encrypt "hello hello" publicKey secretKey
  publicKey2 <- assertJust (binaryToPublicKey (publicKeyToBinary publicKey))
  secretKey2 <- assertJust (binaryToSecretKey (secretKeyToBinary secretKey))
  nonce2 <- assertJust (binaryToNonce (nonceToBinary nonce))
  assertEqual "Roundtripping public key binary serialisation" publicKey publicKey2
  assertEqual "Roundtripping secret key binary serialisation" secretKey secretKey2
  assertEqual "Roundtripping nonce binary serialisation" nonce nonce2

testBinaryWrongLength :: Assertion
testBinaryWrongLength = do
  assertEqual
    "A 16-byte input is rejected for a public key"
    Nothing
    (binaryToPublicKey (BS.replicate 16 0))
  assertEqual
    "A 16-byte input is rejected for a secret key"
    Nothing
    (binaryToSecretKey (BS.replicate 16 0))
  assertEqual
    "A 16-byte input is rejected for a nonce"
    Nothing
    (binaryToNonce (BS.replicate 16 0))
