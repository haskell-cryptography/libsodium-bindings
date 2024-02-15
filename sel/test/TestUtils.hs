module TestUtils where

import Control.Monad.IO.Class (MonadIO, liftIO)
import GHC.Stack
import qualified Test.Tasty.HUnit as Test

assertRight :: MonadIO m => HasCallStack => Either a b -> m b
assertRight (Left _a) = liftIO $ Test.assertFailure "Test return Left instead of Right"
assertRight (Right b) = pure b

assertJust :: MonadIO m => HasCallStack => Maybe a -> m a
assertJust Nothing = liftIO $ Test.assertFailure "Test return Nothing instead of Just"
assertJust (Just b) = pure b
