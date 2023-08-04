{-# LANGUAGE OverloadedStrings #-}

module Test.Hashing.Password where

import Data.Function (on)
import Data.Maybe (isNothing)
import Data.Text (Text)
import qualified Sel.Hashing.Password as Sel
import Test.Tasty
import Test.Tasty.HUnit

spec :: TestTree
spec =
  testGroup
    "Password hashing tests"
    [ testCase "Round-trip test for password hashing" testHashPassword
    , testCase "Consistent password hashing with salt" testHashPasswordWSalt
    ]

testHashPassword :: Assertion
testHashPassword = do
  let password = "hunter2" :: Text
  passwordHash <- Sel.hashText password
  assertBool
    "Password hashing is consistent"
    (Sel.verifyText passwordHash "hunter2")

testHashPasswordWSalt :: Assertion
testHashPasswordWSalt = do
  let hashWSalt s = Sel.hashByteStringWithParams Sel.defaultArgon2Params s
      password = "hunter2"
      cmpPWHashes = on (==) Sel.passwordHashToByteString

  salt1 <- Sel.genSalt
  hashOrig <- hashWSalt salt1 password
  hashOrig' <- hashWSalt salt1 password
  assertBool
    "Password hashing with salt is consistent"
    (cmpPWHashes hashOrig hashOrig')

  hashWoSalt <- Sel.hashByteString password
  assertBool
    "Password hashing with salt differs from without"
    (not $ cmpPWHashes hashOrig hashWoSalt)

  salt2 <- Sel.genSalt
  hashWNewSalt <- hashWSalt salt2 password
  assertBool
    "Password hashing differs with a new salt"
    (not $ cmpPWHashes hashOrig hashWNewSalt)

  assertBool
    "Bogus salt ByteString fails to generate Salt"
    (isNothing (Sel.byteStringToSalt "deadbeef"))
