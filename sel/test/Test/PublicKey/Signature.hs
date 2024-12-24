{-# LANGUAGE OverloadedRecordDot #-}
{-# LANGUAGE OverloadedStrings #-}

module Test.PublicKey.Signature where

import Sel.ByteString.Codec
import Sel.PublicKey.Signature
import Test.Tasty
import Test.Tasty.HUnit
import TestUtils

spec :: TestTree
spec = withKeyPair $ \kp ->
  testGroup "Signature" $
      sequence [ serdes, signing ] kp

serdes :: IO KeyPair -> TestTree
serdes kp = testGroup "Key pair serdes" $
  keyPairCases kp
    [ ("Public key hex round-trip", publicKeyHexRoundTrip)
    , ("Public key bytes round-trip", publicKeyBytesRoundTrip)
    , ("Secret key hex round-trip", secretKeyHexRoundTrip)
    , ("Secret key bytes round-trip", secretKeyBytesRoundTrip)
    , ("Public key extraction", extractPublicKey)
    ]

signing :: IO KeyPair -> TestTree
signing kp = testGroup "Message signing" $
  keyPairCases kp
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

publicKeyHexRoundTrip :: KeyPair -> Assertion
publicKeyHexRoundTrip kp = do
  let encoded = encodeHexBytes kp.public
  decoded <- assertRight $ decodeHexBytes encoded
  assertEqual "Public key hex decode" kp.public decoded

publicKeyBytesRoundTrip :: KeyPair -> Assertion
publicKeyBytesRoundTrip kp = do
  let encoded = encodeHexByteString kp.public
  decoded <- assertRight $ decodeHexByteString encoded
  assertEqual "Public key bytes decode" kp.public decoded

secretKeyHexRoundTrip :: KeyPair -> Assertion
secretKeyHexRoundTrip kp = do
  let encoded = encodeHexBytes $ UnsafeSecretKey kp.secret
  decoded <- assertRight $ decodeHexBytes encoded
  assertEqual "Secret key hex decode" kp.secret decoded

secretKeyBytesRoundTrip :: KeyPair -> Assertion
secretKeyBytesRoundTrip kp = do
  let encoded = encodeHexByteString $ UnsafeSecretKey kp.secret
  decoded <- assertRight $ decodeHexByteString encoded
  assertEqual "Secret key bytes decode" kp.secret decoded

extractPublicKey :: KeyPair -> Assertion
extractPublicKey (KeyPair public secret) =
  assertEqual "Public key extraction" public (publicKey secret)

signAndOpenSelf :: KeyPair -> Assertion
signAndOpenSelf (KeyPair public secret) = do
  let message = "SIGNED"
  signed <- signWith secret message
  let result = verifiedMessage signed public
  assertEqual
    "Open self-signed message"
    (Valid message)
    result

signAndOpenOther :: KeyPair -> Assertion
signAndOpenOther (KeyPair _ secret) = do
  let message = "SIGNED"
  KeyPair otherPublic _ <- keyPair
  signed <- signWith secret message
  let result = verifiedMessage signed otherPublic
  assertEqual
    "Fail to open with another key"
    Invalid
    result

signRoundTrip :: KeyPair -> Assertion
signRoundTrip (KeyPair _ secret) = do
  let message = "SIGNED"
  signed <- signWith secret message
  let unverified = unverifiedMessage signed
      detachedSignature = signature signed
      reconstructed = signedMessage unverified detachedSignature
  assertEqual "Round trip" signed reconstructed

