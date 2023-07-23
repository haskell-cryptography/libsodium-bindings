module TestUtils where

import GHC.Stack
import qualified Test.Tasty.HUnit as Test

assertRight :: HasCallStack => Either a b -> IO b
assertRight (Left _a) = Test.assertFailure "Test return Left instead of Right"
assertRight (Right b) = pure b
