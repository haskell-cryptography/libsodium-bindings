{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ScopedTypeVariables #-}

module Test.SecretKey.EncryptedStream where

import Control.Monad.IO.Class
import Data.ByteString (StrictByteString)
import qualified Data.ByteString as BS
import Data.Either
import Data.Traversable
import Test.Tasty
import Test.Tasty.HUnit

import Sel.SecretKey.EncryptedStream

spec :: TestTree
spec =
  testGroup
    "Encrypted Stream"
    [ testCase "Encrypt and decrypt a stream" testStream
    , testCase "Encrypt and decrypt a stream with additional data" testStreamWithAdditionalData
    ]

testStream :: Assertion
testStream = do
  let messages = ["King", "of", "Kings", "am", "I,", "Osymandias."] :: [StrictByteString]

  (header, secretKey, cipherTexts) <- encryptStream $ \state -> encryptChunks state messages

  decryptionResult' <- decryptStream (header, secretKey) $ \statePtr -> do
    forM cipherTexts $ \ct -> pullFromStream statePtr ct Nothing

  let decryptionResult = streamMessage <$> rights decryptionResult'

  assertEqual
    "Stream is decrypted"
    messages
    decryptionResult
  where
    encryptChunks :: Multipart s -> [StrictByteString] -> IO [CipherText]
    encryptChunks state = \case
      [] -> pure []
      [x] -> do
        result <- pushToStream state x Final Nothing
        case result of
          Left err -> assertFailure (show err)
          Right ct -> pure [ct]
      (x : xs) -> do
        result <- pushToStream state x Message Nothing
        case result of
          Left err -> assertFailure (show err)
          Right ct -> do
            rest <- encryptChunks state xs
            pure $ ct : rest

testStreamWithAdditionalData :: Assertion
testStreamWithAdditionalData = do
  let messages = ["King", "of", "Kings", "am", "I,", "Osymandias."] :: [StrictByteString]
  (header, secretKey, cipherTexts) <- encryptStream $ \state -> encryptChunks state messages

  decryptionResult' <- decryptStream (header, secretKey) $ \statePtr -> do
    forM cipherTexts $ \ct -> pullFromStream statePtr ct (Just (fromIntegral $ BS.length additionalData))
  liftIO $ print decryptionResult'

  let decryptionResult = streamMessage <$> rights decryptionResult'

  assertEqual
    "Stream is decrypted"
    messages
    decryptionResult

  assertEqual
    "Additional data is present"
    []
    (mAdditionalData <$> rights decryptionResult')
  where
    additionalData = "{\"foo\": \"bar\"}"
    encryptChunks :: Multipart s -> [StrictByteString] -> IO [CipherText]
    encryptChunks state = \case
      [] -> pure []
      [x] -> do
        result <- pushToStream state x Final (Just additionalData)
        case result of
          Left err -> assertFailure (show err)
          Right ct -> pure [ct]
      (x : xs) -> do
        result <- pushToStream state x Message (Just additionalData)
        case result of
          Left err -> assertFailure (show err)
          Right ct -> do
            rest <- encryptChunks state xs
            pure $ ct : rest
