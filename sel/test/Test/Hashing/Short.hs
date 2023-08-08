{-# LANGUAGE OverloadedStrings #-}

module Test.Hashing.Short where

import Data.Maybe (fromJust)
import Data.Text (Text)
import qualified Sel.Hashing.Short as Short
import Test.Tasty
import Test.Tasty.HUnit

spec :: TestTree
spec =
  testGroup
    "Password hashing tests"
    [ testCase "Hash a short string with a known salt" testHashPassword
    ]

testHashPassword :: Assertion
testHashPassword = do
  let key = fromJust $ Short.hexTextToShortHashKey "9301a3c5eedf2d783b72dc41fb907964"
  let input = "kwak kwak" :: Text
  hash <- Short.hashText key input
  assertEqual
    "input hashing is consistent"
    (Short.shortHashToHexText hash)
    "d50bb18bee915f21a30e6ea555c34546"
