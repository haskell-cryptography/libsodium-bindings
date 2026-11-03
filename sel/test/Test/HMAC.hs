-- Needed for the deprecated-alias tests only.
{-# LANGUAGE OverloadedStrings #-}
{-# OPTIONS_GHC -Wno-deprecations #-}

module Test.HMAC where

import qualified Data.ByteString as BS
import Test.Tasty
import Test.Tasty.HUnit

import qualified Sel.HMAC.SHA256 as SHA256
import qualified Sel.HMAC.SHA512 as SHA512
import qualified Sel.HMAC.SHA512_256 as SHA512_256
import TestUtils (assertJust, assertRight)

spec :: TestTree
spec =
  testGroup
    "HMAC-SHA2 hashing"
    [ testGroup
        "HMAC-SHA-256"
        [ testCase "Single-message hashing" testSingleHMACSHA256Hashing
        , testCase "Multiple-message hashing" testMultipleHMAC256Hashing
        , testCase "Round-trip authentication key serialisation" testHMAC256AuthenticationKeySerialisation
        , testCase "Round-trip tag serialisation" testHMAC256AuthenticationTagSerialisation
        , testCase "Round-trip authentication key binary serialisation" testHMAC256AuthenticationKeyBinaryRoundtrip
        , testCase "Round-trip tag binary serialisation" testHMAC256AuthenticationTagBinaryRoundtrip
        , testCase "Wrong-length binary input is rejected" testHMAC256BinaryWrongLength
        , testCase "Deprecated binary function is an alias" testHMAC256DeprecatedAlias
        ]
    , testGroup
        "HMAC-SHA-512"
        [ testCase "Single-message hashing" testSingleHMACSHA512Hashing
        , testCase "Multiple-message hashing" testMultipleHMAC512Hashing
        , testCase "Round-trip authentication key serialisation" testHMAC512AuthenticationKeySerialisation
        , testCase "Round-trip tag serialisation" testHMAC512AuthenticationTagSerialisation
        , testCase "Round-trip authentication key binary serialisation" testHMAC512AuthenticationKeyBinaryRoundtrip
        , testCase "Round-trip tag binary serialisation" testHMAC512AuthenticationTagBinaryRoundtrip
        , testCase "Wrong-length binary input is rejected" testHMAC512BinaryWrongLength
        , testCase "Deprecated binary function is an alias" testHMAC512DeprecatedAlias
        ]
    , testGroup
        "HMAC-SHA-512-256"
        [ testCase "Single-message hashing" testSingleHMACSHA512_256Hashing
        , testCase "Multiple-message hashing" testMultipleHMAC512_256Hashing
        , testCase "Round-trip authentication key serialisation" testHMAC512_256AuthenticationKeySerialisation
        , testCase "Round-trip tag serialisation" testHMAC512_256AuthenticationTagSerialisation
        , testCase "Round-trip authentication key binary serialisation" testHMAC512_256AuthenticationKeyBinaryRoundtrip
        , testCase "Round-trip tag binary serialisation" testHMAC512_256AuthenticationTagBinaryRoundtrip
        , testCase "Wrong-length binary input is rejected" testHMAC512_256BinaryWrongLength
        , testCase "Deprecated binary function is an alias" testHMAC512_256DeprecatedAlias
        ]
    ]

-- HMAC-SHA-256

testSingleHMACSHA256Hashing :: Assertion
testSingleHMACSHA256Hashing = do
  key <- SHA256.newAuthenticationKey
  let tag = SHA256.authenticate "Hello, world!" key
  assertBool "message is verified" $
    SHA256.verify tag key "Hello, world!"

testMultipleHMAC256Hashing :: Assertion
testMultipleHMAC256Hashing = do
  key <- assertRight $ SHA256.authenticationKeyFromHexByteString "d7fd28595f186884a88235d1d3c84f836303f58aa69496f2fd76e8a709d5224e"
  actual <- SHA256.withMultipart key $ \multipart -> do
    SHA256.updateMultipart multipart "hunter"
    SHA256.updateMultipart multipart "2"
  assertEqual
    "HMAC-SHA256 tag is consistent"
    "be884a372976dd92e819d55ea7090d0b87377b3ac0773a97a5fdc12523104c35"
    (SHA256.authenticationTagToHexByteString actual)

testHMAC256AuthenticationKeySerialisation :: Assertion
testHMAC256AuthenticationKeySerialisation = do
  key1 <- SHA256.newAuthenticationKey
  let hexKey = SHA256.unsafeAuthenticationKeyToHexByteString key1
  key2 <- assertRight $ SHA256.authenticationKeyFromHexByteString hexKey
  assertEqual "Roundtripping authentication key" key1 key2

testHMAC256AuthenticationTagSerialisation :: Assertion
testHMAC256AuthenticationTagSerialisation = do
  key <- SHA256.newAuthenticationKey
  let tag1 = SHA256.authenticate "Hello, world!" key
  let hexTag = SHA256.authenticationTagToHexByteString tag1
  tag2 <- assertRight $ SHA256.authenticationTagFromHexByteString hexTag
  assertEqual "Roundtripping authentication key" tag1 tag2

-- HMAC-SHA-512

testSingleHMACSHA512Hashing :: Assertion
testSingleHMACSHA512Hashing = do
  key <- SHA512.newAuthenticationKey
  let tag = SHA512.authenticate "Hello, world!" key
  assertBool "message is verified" $
    SHA512.verify tag key "Hello, world!"

testMultipleHMAC512Hashing :: Assertion
testMultipleHMAC512Hashing = do
  key <- assertRight $ SHA512.authenticationKeyFromHexByteString "d7fd28595f186884a88235d1d3c84f836303f58aa69496f2fd76e8a709d5224e"
  actual <- SHA512.withMultipart key $ \multipart -> do
    SHA512.updateMultipart multipart "hunter"
    SHA512.updateMultipart multipart "2"
  assertEqual
    "HMAC-SHA512 tag is consistent"
    "7aad3ea0ca427425ba2fc3cf8078d31e94a62483b7ead624825f9a3fe36bbf5aaf8276e8876faef1a84226e439466774ebc7062495b19a6811cc376bfcccede0"
    (SHA512.authenticationTagToHexByteString actual)

testHMAC512AuthenticationKeySerialisation :: Assertion
testHMAC512AuthenticationKeySerialisation = do
  key1 <- SHA512.newAuthenticationKey
  let hexKey = SHA512.unsafeAuthenticationKeyToHexByteString key1
  key2 <- assertRight $ SHA512.authenticationKeyFromHexByteString hexKey
  assertEqual "Roundtripping authentication key" key1 key2

testHMAC512AuthenticationTagSerialisation :: Assertion
testHMAC512AuthenticationTagSerialisation = do
  key <- SHA512.newAuthenticationKey
  let tag1 = SHA512.authenticate "Hello, world!" key
  let hexTag = SHA512.authenticationTagToHexByteString tag1
  tag2 <- assertRight $ SHA512.authenticationTagFromHexByteString hexTag
  assertEqual "Roundtripping authentication key" tag1 tag2

-- HMAC-SHA-512-256

testSingleHMACSHA512_256Hashing :: Assertion
testSingleHMACSHA512_256Hashing = do
  key <- SHA512_256.newAuthenticationKey
  let tag = SHA512_256.authenticate "Hello, world!" key
  assertBool "message is verified" $
    SHA512_256.verify tag key "Hello, world!"

testMultipleHMAC512_256Hashing :: Assertion
testMultipleHMAC512_256Hashing = do
  key <- assertRight $ SHA512_256.authenticationKeyFromHexByteString "d7fd28595f186884a88235d1d3c84f836303f58aa69496f2fd76e8a709d5224e"
  actual <- SHA512_256.withMultipart key $ \multipart -> do
    SHA512_256.updateMultipart multipart "hunter"
    SHA512_256.updateMultipart multipart "2"
  assertEqual
    "HMAC-SHA512_256 tag is consistent"
    "7aad3ea0ca427425ba2fc3cf8078d31e94a62483b7ead624825f9a3fe36bbf5a"
    (SHA512_256.authenticationTagToHexByteString actual)

testHMAC512_256AuthenticationKeySerialisation :: Assertion
testHMAC512_256AuthenticationKeySerialisation = do
  key1 <- SHA512_256.newAuthenticationKey
  let hexKey = SHA512_256.unsafeAuthenticationKeyToHexByteString key1
  key2 <- assertRight $ SHA512_256.authenticationKeyFromHexByteString hexKey
  assertEqual "Roundtripping authentication key" key1 key2

testHMAC512_256AuthenticationTagSerialisation :: Assertion
testHMAC512_256AuthenticationTagSerialisation = do
  key <- SHA512_256.newAuthenticationKey
  let tag1 = SHA512_256.authenticate "Hello, world!" key
  let hexTag = SHA512_256.authenticationTagToHexByteString tag1
  tag2 <- assertRight $ SHA512_256.authenticationTagFromHexByteString hexTag
  assertEqual "Roundtripping authentication key" tag1 tag2

-- Binary serialisation

testHMAC256AuthenticationKeyBinaryRoundtrip :: Assertion
testHMAC256AuthenticationKeyBinaryRoundtrip = do
  key <- SHA256.newAuthenticationKey
  key2 <- assertJust (SHA256.binaryToAuthenticationKey (SHA256.authenticationKeyToBinary key))
  assertEqual "Roundtripping authentication key binary serialisation" key key2

testHMAC256AuthenticationTagBinaryRoundtrip :: Assertion
testHMAC256AuthenticationTagBinaryRoundtrip = do
  key <- SHA256.newAuthenticationKey
  let tag = SHA256.authenticate "Hello, world!" key
  tag2 <- assertJust (SHA256.binaryToAuthenticationTag (SHA256.authenticationTagToBinary tag))
  assertEqual "Roundtripping authentication tag binary serialisation" tag tag2

testHMAC256BinaryWrongLength :: Assertion
testHMAC256BinaryWrongLength = do
  assertEqual
    "A 16-byte input is rejected for an authentication key"
    Nothing
    (SHA256.binaryToAuthenticationKey (BS.replicate 16 0))
  assertEqual
    "A 16-byte input is rejected for an authentication tag"
    Nothing
    (SHA256.binaryToAuthenticationTag (BS.replicate 16 0))

testHMAC256DeprecatedAlias :: Assertion
testHMAC256DeprecatedAlias = do
  key <- SHA256.newAuthenticationKey
  assertEqual
    "The deprecated function returns raw binary like its replacement"
    (SHA256.authenticationKeyToBinary key)
    (SHA256.unsafeAuthenticationKeyToBinary key)

testHMAC512AuthenticationKeyBinaryRoundtrip :: Assertion
testHMAC512AuthenticationKeyBinaryRoundtrip = do
  key <- SHA512.newAuthenticationKey
  key2 <- assertJust (SHA512.binaryToAuthenticationKey (SHA512.authenticationKeyToBinary key))
  assertEqual "Roundtripping authentication key binary serialisation" key key2

testHMAC512AuthenticationTagBinaryRoundtrip :: Assertion
testHMAC512AuthenticationTagBinaryRoundtrip = do
  key <- SHA512.newAuthenticationKey
  let tag = SHA512.authenticate "Hello, world!" key
  tag2 <- assertJust (SHA512.binaryToAuthenticationTag (SHA512.authenticationTagToBinary tag))
  assertEqual "Roundtripping authentication tag binary serialisation" tag tag2

testHMAC512BinaryWrongLength :: Assertion
testHMAC512BinaryWrongLength = do
  assertEqual
    "A 16-byte input is rejected for an authentication key"
    Nothing
    (SHA512.binaryToAuthenticationKey (BS.replicate 16 0))
  assertEqual
    "A 16-byte input is rejected for an authentication tag"
    Nothing
    (SHA512.binaryToAuthenticationTag (BS.replicate 16 0))

testHMAC512_256AuthenticationKeyBinaryRoundtrip :: Assertion
testHMAC512_256AuthenticationKeyBinaryRoundtrip = do
  key <- SHA512_256.newAuthenticationKey
  key2 <- assertJust (SHA512_256.binaryToAuthenticationKey (SHA512_256.authenticationKeyToBinary key))
  assertEqual "Roundtripping authentication key binary serialisation" key key2

testHMAC512_256AuthenticationTagBinaryRoundtrip :: Assertion
testHMAC512_256AuthenticationTagBinaryRoundtrip = do
  key <- SHA512_256.newAuthenticationKey
  let tag = SHA512_256.authenticate "Hello, world!" key
  tag2 <- assertJust (SHA512_256.binaryToAuthenticationTag (SHA512_256.authenticationTagToBinary tag))
  assertEqual "Roundtripping authentication tag binary serialisation" tag tag2

testHMAC512_256BinaryWrongLength :: Assertion
testHMAC512_256BinaryWrongLength = do
  assertEqual
    "A 16-byte input is rejected for an authentication key"
    Nothing
    (SHA512_256.binaryToAuthenticationKey (BS.replicate 16 0))
  assertEqual
    "A 16-byte input is rejected for an authentication tag"
    Nothing
    (SHA512_256.binaryToAuthenticationTag (BS.replicate 16 0))

testHMAC512DeprecatedAlias :: Assertion
testHMAC512DeprecatedAlias = do
  key <- SHA512.newAuthenticationKey
  assertEqual
    "The deprecated function returns raw binary like its replacement"
    (SHA512.authenticationKeyToBinary key)
    (SHA512.unsafeAuthenticationKeyToBinary key)

testHMAC512_256DeprecatedAlias :: Assertion
testHMAC512_256DeprecatedAlias = do
  key <- SHA512_256.newAuthenticationKey
  assertEqual
    "The deprecated function returns raw binary like its replacement"
    (SHA512_256.authenticationKeyToBinary key)
    (SHA512_256.unsafeAuthenticationKeyToBinary key)
