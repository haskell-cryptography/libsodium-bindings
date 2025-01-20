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

serdes :: IO (PublicKey, SecretKey) -> TestTree
serdes kp =
  testGroup "Key pair serdes" $
    keyPairCases
      kp
      [ ("Public key round-trip", publicKeyRoundTrip)
      , ("Secret key round-trip", secretKeyRoundTrip)
      , ("Public key extraction", publicKeyExtraction)
      ]

signing :: IO (PublicKey, SecretKey) -> TestTree
signing kp =
  testGroup "Message signing" $
    keyPairCases
      kp
      [ ("Sign and open with the same key", signAndOpenSelf)
      , ("Sign and open with another key", signAndOpenOther)
      , ("Detached signature round-trip", signRoundTrip)
      ]

keyPairCases :: IO (PublicKey, SecretKey) -> [(String, (PublicKey, SecretKey) -> Assertion)] -> [TestTree]
keyPairCases = fmap . uncurry . usingKeyPair

withKeyPair :: (IO (PublicKey, SecretKey) -> TestTree) -> TestTree
withKeyPair = withResource generateKeyPair mempty

usingKeyPair :: IO (PublicKey, SecretKey) -> String -> ((PublicKey, SecretKey) -> Assertion) -> TestTree
usingKeyPair kp testName test = testCase testName (test =<< kp)

publicKeyRoundTrip :: (PublicKey, SecretKey) -> Assertion
publicKeyRoundTrip (public, _) = do
  let encoded = encodePublicKeyHexByteString public
  decoded <- assertRight $ decodePublicKeyHexByteString encoded
  assertEqual "Public key hex decode" public decoded

secretKeyRoundTrip :: (PublicKey, SecretKey) -> Assertion
secretKeyRoundTrip (_, secret) = do
  let encoded = unsafeEncodeSecretKeyHexByteString secret
  decoded <- assertRight $ decodeSecretKeyHexByteString encoded
  assertEqual "Secret key hex decode" secret decoded

publicKeyExtraction :: (PublicKey, SecretKey) -> Assertion
publicKeyExtraction (public, secret) =
  assertEqual "Public key extraction" public (publicKey secret)

signAndOpenSelf :: (PublicKey, SecretKey) -> Assertion
signAndOpenSelf (public, secret) = do
  let message = "SIGNED"
  signed <- signMessage message secret
  let result = openMessage signed public
  assertEqual
    "Open self-signed message"
    (Just message)
    result

signAndOpenOther :: (PublicKey, SecretKey) -> Assertion
signAndOpenOther (_, secret) = do
  let message = "SIGNED"
  (otherPublic, _) <- generateKeyPair
  signed <- signMessage message secret
  let result = openMessage signed otherPublic
  assertEqual
    "Fail to open with another key"
    Nothing
    result

signRoundTrip :: (PublicKey, SecretKey) -> Assertion
signRoundTrip (_, secret) = do
  let message = "SIGNED"
  signed <- signMessage message secret
  let unverified = unsafeGetMessage signed
      detachedSignature = getSignature signed
      reconstructed = mkSignature unverified detachedSignature
  assertEqual "Round trip" signed reconstructed
