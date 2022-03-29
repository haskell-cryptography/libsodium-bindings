module Main where

import qualified HashingTests
import Test.Tasty

main :: IO ()
main = do
  defaultMain . testGroup "Libsodium bindings tests" $ spec

spec :: [TestTree]
spec = [HashingTests.spec]
