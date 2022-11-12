module Main where

import Test.Tasty

import qualified Test.GenericHashing as GenericHashing

main :: IO ()
main = do
  defaultMain . testGroup "libsodium-bindings tests" $ specs

specs :: [TestTree]
specs =
  [ GenericHashing.spec
  ]
