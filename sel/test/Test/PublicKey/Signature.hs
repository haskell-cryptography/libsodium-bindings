{-# LANGUAGE OverloadedRecordDot #-}
{-# LANGUAGE OverloadedStrings #-}

module Test.PublicKey.Signature where

import Sel.PublicKey.Signature
import Test.Tasty
import Test.Tasty.HUnit
import TestUtils

spec :: TestTree
spec = withKeyPair $ \kp ->
  testGroup "Signature" $
    sequence [serdes, signing] kp

serdes :: IO KeyPair -> TestTree
serdes kp =
  testGroup "Key pair serdes" $
    keyPairCases
      kp
      [ ("Public key round-trip", publicKeyRoundTrip)
      , ("Secret key round-trip", secretKeyRoundTrip)
      , ("Public key extraction", publicKeyExtraction)
      ]

signing :: IO KeyPair -> TestTree
signing kp =
  testGroup "Message signing" $
    keyPairCases
      kp
      [ ("Sign and open with the same key", signAndOpenSelf)
      , ("Sign and open with another key", signAndOpenOther)
      , ("Detached signature round-trip", signRoundTrip)
      ]

keyPairCases :: IO KeyPair -> [(String, KeyPair -> Assertion)] -> [TestTree]
keyPairCases = fmap . uncurry . usingKeyPair

withKeyPair :: (IO KeyPair -> TestTree) -> TestTree
withKeyPair = withResource keyPair mempty

usingKeyPair :: IO KeyPair -> String -> (KeyPair -> Assertion) -> TestTree
usingKeyPair kp testName test = testCase testName (test =<< kp)

publicKeyRoundTrip :: KeyPair -> Assertion
publicKeyRoundTrip kp = do
  let encoded = encodePublicKeyHexByteString kp.public
  decoded <- assertRight $ decodePublicKeyHexByteString encoded
  assertEqual "Public key hex decode" kp.public decoded

secretKeyRoundTrip :: KeyPair -> Assertion
secretKeyRoundTrip kp = do
  let encoded = encodeSecretKeyHexByteString $ UnsafeSecretKey kp.secret
  decoded <- assertRight $ decodeSecretKeyHexByteString encoded
  assertEqual "Secret key hex decode" kp.secret decoded

publicKeyExtraction :: KeyPair -> Assertion
publicKeyExtraction kp =
  assertEqual "Public key extraction" kp.public (publicKey kp.secret)

signAndOpenSelf :: KeyPair -> Assertion
signAndOpenSelf kp = do
  let message = "SIGNED"
  signed <- signWith kp.secret message
  let result = verifiedMessage signed kp.public
  assertEqual
    "Open self-signed message"
    (Valid message)
    result

signAndOpenOther :: KeyPair -> Assertion
signAndOpenOther kp = do
  let message = "SIGNED"
  other <- keyPair
  signed <- signWith kp.secret message
  let result = verifiedMessage signed other.public
  assertEqual
    "Fail to open with another key"
    Invalid
    result

signRoundTrip :: KeyPair -> Assertion
signRoundTrip kp = do
  let message = "SIGNED"
  signed <- signWith kp.secret message
  let unverified = unverifiedMessage signed
      detachedSignature = signature signed
      reconstructed = signedMessage unverified detachedSignature
  assertEqual "Round trip" signed reconstructed
