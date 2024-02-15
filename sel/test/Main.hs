module Main where

import Test.Tasty

import LibSodium.Bindings.Main (sodiumInit)
import qualified Test.HMAC as HMAC
import qualified Test.Hashing as Hashing
import qualified Test.Hashing.Password as Password
import qualified Test.Hashing.SHA2 as Hashing.SHA2
import qualified Test.Hashing.Short as Short
import qualified Test.PublicKey.Cipher as PublicKey.Cipher
import qualified Test.PublicKey.Seal as PublicKey.Seal
import qualified Test.PublicKey.Signature as PublicKey.Signature
import qualified Test.Scrypt as Scrypt
import qualified Test.SecretKey.Authentication as SecretKey.Authentication
import qualified Test.SecretKey.Cipher as SecretKey.Cipher
import qualified Test.SecretKey.Stream as SecretKey.Stream

main :: IO ()
main = do
  sodiumInit
  defaultMain . testGroup "sel tests" $ specs

specs :: [TestTree]
specs =
  [ Hashing.spec
  , Password.spec
  , Short.spec
  , PublicKey.Signature.spec
  , PublicKey.Cipher.spec
  , PublicKey.Seal.spec
  , Hashing.SHA2.spec
  , SecretKey.Cipher.spec
  , SecretKey.Authentication.spec
  , SecretKey.Stream.spec
  , HMAC.spec
  , Scrypt.spec
  ]
