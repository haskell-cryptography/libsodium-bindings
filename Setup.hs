module Main where

import Control.Monad
import Distribution.Simple
import Distribution.System (OS(..), buildOS)
import Debug.Trace
import Distribution.Types.LocalBuildInfo
import System.Process (system)
import System.FilePath ((</>), (<.>))
import System.Directory (copyFile)

main = defaultMainWithHooks $
  simpleUserHooks
    { postConf = \_args _configFlags _packageDescription localBuildInfo -> do
        let destinationPath = traceId $ buildDir localBuildInfo </> "libsodium" <.> "a"
        case buildOS of
          Windows -> do
            copyFile ("winlibs" </> "libsodium" <.> "lib") destinationPath
          _ -> do
            void $ system $ "cd cbits/libsodium-stable/ && ./configure && make -j && cp -v ./src/libsodium/.libs/libsodium.a " <> destinationPath
    }
