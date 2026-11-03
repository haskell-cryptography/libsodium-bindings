{-# LANGUAGE OverloadedStrings #-}

module Test.Hashing.Short where

import qualified Data.ByteString as BS
import Data.Maybe (fromJust)
import Data.Text (Text)
import Test.Tasty
import Test.Tasty.HUnit

import qualified Sel.Hashing.Short as Short
import TestUtils (assertJust)

spec :: TestTree
spec =
  testGroup
    "Password hashing tests"
    [ testCase "Hash a short string with a known salt" testHashPassword
    , testCase "Round-trip short hash binary serialisation" testBinaryRoundtrip
    ]

testHashPassword :: Assertion
testHashPassword = do
  let key = fromJust $ Short.hexTextToShortHashKey "9301a3c5eedf2d783b72dc41fb907964"
  let input = "kwak kwak" :: Text
  let hash = Short.hashText key input
  assertEqual
    "input hashing is consistent"
    (Short.shortHashToHexText hash)
    "d50bb18bee915f21a30e6ea555c34546"

testBinaryRoundtrip :: Assertion
testBinaryRoundtrip = do
  let key = fromJust $ Short.hexTextToShortHashKey "9301a3c5eedf2d783b72dc41fb907964"
      hash = Short.hashText key "kwak kwak"
  hash2 <- assertJust (Short.binaryToShortHash (Short.shortHashToBinary hash))
  assertEqual
    "Short hash remains the same when binary-serialised"
    hash
    hash2
  assertEqual
    "An 8-byte input is rejected for a short hash"
    Nothing
    (Short.binaryToShortHash (BS.replicate 8 0))
