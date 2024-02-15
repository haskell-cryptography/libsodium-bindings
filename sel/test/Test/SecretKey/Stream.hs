{-# LANGUAGE OverloadedStrings #-}

module Test.SecretKey.Stream where

import Control.Monad (forM)
import qualified Data.List as List
import qualified Sel.SecretKey.Stream as Stream
import Test.Tasty
import Test.Tasty.HUnit
import TestUtils

spec :: TestTree
spec =
  testGroup
    "Secret Key Encrypted Stream tests"
    [ testCase "Encrypt a stream with a secret key" testEncryptStream
    -- , testCase "Round-trip secret key serialisation" testSecretKeySerdeRoundtrip
    -- , testCase "Round-trip ciphertext serialisation" testHashSerdeRoundtrip
    ]

testEncryptStream :: Assertion
testEncryptStream = do
  secretKey <- Stream.newSecretKey
  (header, encryptedPayload) <- Stream.encryptStream secretKey $ \multipart -> do
    let messages = ["Hello", "abcdf", "world"]
    ciphers <- forM (List.init messages) (Stream.encryptChunk multipart Stream.Message)
    lastMessage <- Stream.encryptChunk multipart Stream.Final (List.last messages)
    pure $ List.map Stream.ciphertextToHexByteString (ciphers <> [lastMessage])

  mResult <- Stream.decryptStream secretKey header $ \multipart -> do
    forM encryptedPayload $ \cipherText -> do
      Stream.decryptChunk multipart cipherText
  result <- assertJust mResult
  print result
