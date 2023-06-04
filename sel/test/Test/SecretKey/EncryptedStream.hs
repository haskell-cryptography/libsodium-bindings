{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ScopedTypeVariables #-}

module Test.SecretKey.EncryptedStream where

import Control.Monad (void)
import Data.ByteString (StrictByteString)
import qualified Data.Text.IO as Text
import Data.Traversable
import qualified Foreign
import Test.Tasty
import Test.Tasty.HUnit

import LibSodium.Bindings.SecretStream (cryptoSecretStreamXChaCha20Poly1305StateBytes)
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
      encryptChunks state [x] = do
        result <- pushToStream state x Nothing Final
        case result of
          Left err -> assertFailure (show err)
          Right ct -> pure [ct]
      encryptChunks state (x : xs) = do
        result <- pushToStream state x Nothing Message
        case result of
          Left err -> assertFailure (show err)
          Right ct -> do
            rest <- encryptChunks state xs
            pure $ ct : rest
  (header, secretKey, cipherTexts) <- encryptStream $ \state -> do
    encryptChunks state messages
  Text.putStrLn $ mconcat $ fmap cipherTextToHexText cipherTexts

  (decryptionResult' :: [StreamResult]) <- do
    Foreign.allocaBytes (fromIntegral cryptoSecretStreamXChaCha20Poly1305StateBytes) $ \statePtr -> do
      void $ initPullStream (Multipart statePtr) header secretKey
      forM cipherTexts $ \ct -> do
        result <- pullFromStream (Multipart statePtr) ct
        case result of
          Left err -> assertFailure (show err)
          Right sr -> pure sr

  let decryptionResult = streamMessage <$> decryptionResult'
  assertEqual
    "Message is well-opened with the correct key and nonce"
    messages
    decryptionResult
