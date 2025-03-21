{-# LANGUAGE OverloadedStrings #-}

module Test.SecretKey.Stream where

import Data.ByteString (StrictByteString)
import Test.Tasty
import Test.Tasty.HUnit

import qualified Sel.SecretKey.Stream as Stream
import TestUtils

spec :: TestTree
spec =
  testGroup
    "Secret Key Encrypted Stream tests"
    [ testCase "Encrypt a stream with a secret key" testEncryptStream
    , testCase "Round-trip secret key serialisation" testSecretKeySerdeRoundtrip
    , testCase "Round-trip ciphertext serialisation" testCiphertextSerdeRoundtrip
    -- , testCase "Round-trip header serialisation" testHeaderSerdeRoundtrip
    ]

testEncryptStream :: Assertion
testEncryptStream = do
  secretKey <- Stream.newSecretKey
  let messages = ["Hello", "abcdf", "world"]
      ad = map Just [Stream.AdditionalData "Goodbye", Stream.AdditionalData "31337", Stream.AdditionalData "planet"]
      messagesAndAd = zip ad messages
  (header, ciphertexts) <- Stream.encryptList secretKey messagesAndAd
  let ciphertextsAndAd = zip ad ciphertexts
  mResult <- Stream.decryptList secretKey header ciphertextsAndAd
  result <- assertJust mResult

  assertEqual
    "Expected result"
    result
    messages

testSecretKeySerdeRoundtrip :: Assertion
testSecretKeySerdeRoundtrip = do
  secretKey1 <- Stream.newSecretKey
  let hexSecretKey1 = Stream.unsafeSecretKeyToHexByteString secretKey1
  secretKey2 <- assertRight $ Stream.secretKeyFromHexByteString hexSecretKey1

  assertEqual
    "The keys remain equal"
    secretKey1
    secretKey2

testCiphertextSerdeRoundtrip :: Assertion
testCiphertextSerdeRoundtrip = do
  secretKey <- Stream.newSecretKey
  let message = "hello" :: StrictByteString
      additionalData = Stream.AdditionalData "this is additional data"
  (_, encryptedPayload1) <- Stream.encryptStream secretKey $ \multipart -> do
    Stream.encryptChunk multipart Stream.Final (Just additionalData) message

  let hexCiphertext = Stream.ciphertextToHexByteString encryptedPayload1
  encryptedPayload2 <- assertRight $ Stream.ciphertextFromHexByteString hexCiphertext

  assertEqual
    "The ciphertexts remain equal"
    encryptedPayload1
    encryptedPayload2
