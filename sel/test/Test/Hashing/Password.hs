{-# LANGUAGE OverloadedStrings #-}

module Test.Hashing.Password where

import Data.Function (on)
import Data.Maybe (isNothing)
import Data.Text (Text)
import qualified Data.Text as Text
import Test.Tasty
import Test.Tasty.HUnit

import qualified Sel.Hashing.Password as Sel

spec :: TestTree
spec =
  testGroup
    "Password hashing tests"
    [ testCase "Round-trip test for password hashing" testRoundtripHash
    , testCase "Consistent password hashing with salt" testHashPasswordWSalt
    , testCase "ASCII representation" testASCIIRepresentation
    ]

testRoundtripHash :: Assertion
testRoundtripHash = do
  let password = "hunter2" :: Text
  passwordHash <- Sel.hashText password
  let passwordHash' = Sel.asciiByteStringToPasswordHash $ Sel.passwordHashToByteString passwordHash

  assertEqual
    "Original hash and hash from bytestring are the same"
    passwordHash
    passwordHash'

  assertBool
    "Password hashing is consistent"
    (Sel.verifyText passwordHash "hunter2")

  assertBool
    "Password hashing is consistent"
    (Sel.verifyText passwordHash' "hunter2")

testHashPasswordWSalt :: Assertion
testHashPasswordWSalt = do
  let hashWSalt s = Sel.hashByteStringWithParams Sel.defaultArgon2Params s
      password = "hunter2"
      cmpPWHashes = on (==) Sel.passwordHashToByteString

  salt1 <- Sel.genSalt
  let hashOrig = hashWSalt salt1 password
      hashOrig' = hashWSalt salt1 password
  assertBool
    "Password hashing with salt is consistent"
    (cmpPWHashes hashOrig hashOrig')

  hashWoSalt <- Sel.hashByteString password
  assertBool
    "Password hashing with salt differs from without"
    (not $ cmpPWHashes hashOrig hashWoSalt)

  salt2 <- Sel.genSalt
  let hashWNewSalt = hashWSalt salt2 password
  assertBool
    "Password hashing differs with a new salt"
    (not $ cmpPWHashes hashOrig hashWNewSalt)

  assertBool
    "Bogus salt ByteString fails to generate Salt"
    (isNothing (Sel.hexByteStringToSalt "deadbeef"))

testASCIIRepresentation :: Assertion
testASCIIRepresentation = do
  hash <- Sel.hashByteString "hunter3"
  let textHash = Sel.passwordHashToText hash
  assertBool
    "Textual representation is stable using passwordHashToText"
    ("$argon2id$v=19$m=262144,t=3,p=1$" `Text.isPrefixOf` textHash)

  let bsHash = Sel.passwordHashToByteString hash
  let hash2 = Sel.asciiByteStringToPasswordHash bsHash
  assertEqual
    "Can import hash"
    hash2
    hash
