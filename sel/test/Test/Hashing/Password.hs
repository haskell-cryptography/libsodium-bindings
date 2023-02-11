{-# LANGUAGE OverloadedStrings #-}

module Test.Hashing.Password where

import Data.Text (Text)
import qualified Sel.Hashing.Password as Sel
import Test.Tasty
import Test.Tasty.HUnit

spec :: TestTree
spec =
  testGroup
    "Password hashing tests"
    [ testCase "Round-trip test for password hashing with random salt" testHashPassword
    ]

testHashPassword :: Assertion
testHashPassword = do
  let password = "hunter2" :: Text
  passwordHash <- Sel.hashText password
  assertBool
    "Password hashing is consistent"
    (Sel.verifyText passwordHash "hunter2")
