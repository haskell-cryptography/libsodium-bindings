module Main where

import Control.Monad
import Distribution.Simple
import Distribution.System (OS(..), buildOS)
import Debug.Trace
import Distribution.Types.LocalBuildInfo
import System.Process (system)

main = defaultMainWithHooks $
  simpleUserHooks
    { postConf = \_args _configFlags _packageDescription localBuildInfo -> do
        case buildOS of
          Windows -> error "Build is not supported on Windows yet."
          _ ->
            let destinationPath = traceId $ buildDir localBuildInfo <> "/libsodium.a"
             in void $ system $ "cd cbits/libsodium-stable/ && ./configure && make -j && cp -v ./src/libsodium/.libs/libsodium.a " <> destinationPath
    }
