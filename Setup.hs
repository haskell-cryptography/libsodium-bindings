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
        -- Cabal, and indeed, GHC, don't understand the .lib extension on
        -- Windows, so we have the same name everywhere.
        let destinationPath = traceId $ buildDir localBuildInfo </> "libsodium" <.> "a"
        case buildOS of
          Windows -> do
            -- We're in a bit of a bind when it comes to Windows. The chief
            -- problem is that the _only_ shell we have access to is CMD.EXE:
            -- this means that, even though we _could_ have Autotools access in
            -- theory (since GHC needs MinGW, which comes with the Autotools),
            -- we can't use them. Furthermore, we can't be clever and do a
            -- Visual Studio build, for two reasons:
            --
            -- 1. It would require our users to have Visual Studio installed,
            --    which is quite onerous.
            -- 2. We would have to detect where Visual Studio put the compiler,
            --    then drive a Visual Studio build, from the command line,
            --    _manually_. This is even _more_ onerous!
            --
            -- Thus, we use a bundled static prebuild. This is not ideal, as it
            -- bloats the distribution, but there's very little we can do about
            -- this.
            copyFile ("winlibs" </> "libsodium" <.> "lib") destinationPath
          _ -> do
            -- Everything else is some flavour of POSIX. Because we can expect a
            -- POSIX shell, we're good to use the Autotools to build in-place.
            void $ system $ "cd cbits/libsodium-stable/ && ./configure && make -j && cp -v ./src/libsodium/.libs/libsodium.a " <> destinationPath
    }
