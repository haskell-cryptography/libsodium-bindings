module Main where

import Test.Tasty

import LibSodium.Bindings.Main (sodiumInit)
import qualified Test.Hashing as Hashing
import qualified Test.Hashing.Password as Password
import qualified Test.Hashing.SHA2 as SHA2
import qualified Test.PublicKey.AuthenticatedEncryption as PublicKey.AuthenticatedEncryption
import qualified Test.PublicKey.Signature as PublicKey.Signature
import qualified Test.SecretKey.AuthenticatedEncryption as SecretKey.AuthenticatedEncryption

main :: IO ()
main = do
  sodiumInit
  defaultMain . testGroup "sel tests" $ specs

specs :: [TestTree]
specs =
  [ Hashing.spec
  , Password.spec
  , PublicKey.Signature.spec
  , PublicKey.AuthenticatedEncryption.spec
  , SHA2.spec
  , SecretKey.AuthenticatedEncryption.spec
  ]
