{-# LANGUAGE OverloadedStrings #-}

module Test.Hashing.SHA2 where

import Data.Text (Text)
import Test.Tasty
import Test.Tasty.HUnit

import qualified Sel.Hashing.SHA256 as SHA256
import qualified Sel.Hashing.SHA512 as SHA512

spec :: TestTree
spec =
  testGroup
    "SHA2 hashing"
    [ testGroup
        "SHA-256"
        [ testCase "SHA-256 single-message hashing" testSingleHashSHA256
        , testCase "SHA-256 multi-part message hashing" testMultipartHashSH256
        ]
    , testGroup
        "SHA-512"
        [ testCase "SHA-512 single-message hashing" testSingleHashSHA512
        , testCase "SHA-512 multi-part message hashing" testMultipartHashSH512
        ]
    ]

testSingleHashSHA512 :: Assertion
testSingleHashSHA512 = do
  let password = "hunter2" :: Text
      actual = SHA512.hashText password
  assertEqual
    "SHA-512 hashing is consistent"
    (SHA512.hashToHexByteString actual)
    "6b97ed68d14eb3f1aa959ce5d49c7dc612e1eb1dafd73b1e705847483fd6a6c809f2ceb4e8df6ff9984c6298ff0285cace6614bf8daa9f0070101b6c89899e22"

testMultipartHashSH512 :: Assertion
testMultipartHashSH512 = do
  actual <- SHA512.withMultipart $ \multipart -> do
    SHA512.updateMultipart multipart "hunter"
    SHA512.updateMultipart multipart "2"
  assertEqual
    "SHA-512 hashing is consistent"
    (SHA512.hashToHexByteString actual)
    "6b97ed68d14eb3f1aa959ce5d49c7dc612e1eb1dafd73b1e705847483fd6a6c809f2ceb4e8df6ff9984c6298ff0285cace6614bf8daa9f0070101b6c89899e22"

testSingleHashSHA256 :: Assertion
testSingleHashSHA256 = do
  let password = "hunter2" :: Text
      actual = SHA256.hashText password
  assertEqual
    "SHA-256 hashing is consistent"
    (SHA256.hashToHexByteString actual)
    "f52fbd32b2b3b86ff88ef6c490628285f482af15ddcb29541f94bcf526a3f6c7"

testMultipartHashSH256 :: Assertion
testMultipartHashSH256 = do
  actual <- SHA256.withMultipart $ \multipart -> do
    SHA256.updateMultipart multipart "hunter"
    SHA256.updateMultipart multipart "2"
  assertEqual
    "SHA-256 hashing is consistent"
    (SHA256.hashToHexByteString actual)
    "f52fbd32b2b3b86ff88ef6c490628285f482af15ddcb29541f94bcf526a3f6c7"
