{-# LANGUAGE OverloadedStrings #-}

module Test.PublicKey.Signature where

import qualified Data.ByteString as BS
import Test.Tasty
import Test.Tasty.HUnit

import Sel.Hashing (hashByteString, hashToBinary)
import Sel.PublicKey.Signature
import TestUtils (assertJust)

spec :: TestTree
spec =
  testGroup
    "Signing tests"
    [ testCase "Sign a message with a public key and decrypt it with a secret key" testSignMessage
    , testCase "Round-trip public key binary serialisation" testPublicKeyBinaryRoundtrip
    , testCase "Round-trip secret key binary serialisation" testSecretKeyBinaryRoundtrip
    , testCase "Wrong-length binary input is rejected" testBinaryWrongLength
    , testCase "Hash a serialised public key" testHashSerialisedPublicKey
    , testCase "Sign and open with re-imported keys" testSignVerifyWithImportedKeys
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

testPublicKeyBinaryRoundtrip :: Assertion
testPublicKeyBinaryRoundtrip = do
  (publicKey, _) <- generateKeyPair
  let roundtripped = fmap publicKeyToBinary (binaryToPublicKey (publicKeyToBinary publicKey))
  assertEqual
    "Public key is recovered from its binary form"
    (Just (publicKeyToBinary publicKey))
    roundtripped

testSecretKeyBinaryRoundtrip :: Assertion
testSecretKeyBinaryRoundtrip = do
  (_, secretKey) <- generateKeyPair
  let roundtripped = fmap secretKeyToBinary (binaryToSecretKey (secretKeyToBinary secretKey))
  assertEqual
    "Secret key is recovered from its binary form"
    (Just (secretKeyToBinary secretKey))
    roundtripped

testBinaryWrongLength :: Assertion
testBinaryWrongLength = do
  assertBool
    "A 16-byte input is rejected for a public key"
    (binaryToPublicKey (BS.replicate 16 0) == Nothing)
  assertBool
    "A 16-byte input is rejected for a secret key"
    (binaryToSecretKey (BS.replicate 16 0) == Nothing)

testHashSerialisedPublicKey :: Assertion
testHashSerialisedPublicKey = do
  (publicKey, _) <- generateKeyPair
  roundtripped <- assertJust (binaryToPublicKey (publicKeyToBinary publicKey))
  let hashed = hashByteString Nothing (publicKeyToBinary roundtripped)
  assertEqual
    "Hashing a roundtripped public key equals hashing the original serialised bytes"
    (hashToBinary (hashByteString Nothing (publicKeyToBinary publicKey)))
    (hashToBinary hashed)
  assertEqual
    "The generic hash default size is 32 bytes"
    32
    (BS.length (hashToBinary hashed))

testSignVerifyWithImportedKeys :: Assertion
testSignVerifyWithImportedKeys = do
  (publicKey, secretKey) <- generateKeyPair
  importedSecretKey <- assertJust (binaryToSecretKey (secretKeyToBinary secretKey))
  importedPublicKey <- assertJust (binaryToPublicKey (publicKeyToBinary publicKey))
  signedMessage <- signMessage "hello hello" importedSecretKey
  let result = openMessage signedMessage importedPublicKey
  assertEqual
    "Message is well-opened with the imported keys"
    (Just "hello hello")
    result
