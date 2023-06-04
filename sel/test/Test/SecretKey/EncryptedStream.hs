{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ScopedTypeVariables #-}

module Test.SecretKey.EncryptedStream where

import Data.ByteString (StrictByteString)
import qualified Data.List as List
import Test.Tasty
import Test.Tasty.HUnit

import Data.Maybe (catMaybes)
import Data.Traversable (forM)
import Sel.SecretKey.EncryptedStream

spec :: TestTree
spec =
  testGroup
    "Encrypted Stream"
    [ testCase "Encrypt and decrypt a stream" testStream
    ]

testStream :: Assertion
testStream = do
  let messages = ["King", "of", "Kings", "am", "I,", "Osymandias."]
  let encryptChunks :: Multipart s -> [StrictByteString] -> IO [CipherText]
      encryptChunks _ [] = pure []
      encryptChunks state [x] = List.singleton <$> pushToStream state x Nothing Final
      encryptChunks state (x : xs) = do
        cipherText <- pushToStream state x Nothing Message
        rest <- encryptChunks state xs
        pure $ cipherText : rest
  (header, secretKey, cipherTexts) <- encryptStream $ \state -> do
    encryptChunks state messages

  (decryptionResult' :: [Maybe StreamResult]) <- decryptStream (header, secretKey) $ \state -> do
    forM cipherTexts (pullFromStream state)
  let decryptionResult = streamMessage <$> catMaybes decryptionResult'
  assertEqual
    "Message is well-opened with the correct key and nonce"
    messages
    decryptionResult
