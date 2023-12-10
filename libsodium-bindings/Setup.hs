module Main where

import Control.Monad
import Debug.Trace
import Distribution.Simple
import Distribution.Simple.Setup
import Distribution.System
import Distribution.Types.Flag
import Distribution.Types.LocalBuildInfo
import System.Directory (copyFile, doesFileExist, renameFile, withCurrentDirectory)
import System.FilePath ((<.>), (</>))
import System.Process (system)

main =
  defaultMainWithHooks $
    simpleUserHooks
      { postConf = \_args configFlags _packageDescription localBuildInfo ->
          case lookupFlagAssignment (mkFlagName "bundled-libsodium") (configConfigurationsFlags configFlags) of
            Just True -> do
              putStrLn "Building with the bundled libsodium 1.0.18-stable"
              -- Cabal, and indeed, GHC, don't understand the .lib extension on
              -- Windows, so we have the same name everywhere.
              let destinationPath = traceId $ buildDir localBuildInfo </> "libCsodium" <.> "a"
              case (buildOS, buildArch) of
                (Windows, X86_64) -> do
                  copyFile ("binaries" </> "winlibs" </> "libsodium" <.> "a") destinationPath
                (Linux, X86_64) -> do
                  copyFile ("binaries" </> "x86_64-unknown-linux" </> "libsodium" <.> "a") destinationPath
                (FreeBSD, X86_64) -> do
                  copyFile ("binaries" </> "x86_64-unknown-freebsd" </> "libsodium" <.> "a") destinationPath
                (os, arch) ->
                  putStrLn $ "Static libsodium builds for " <> show arch <> "-unknown-" <> show os <> " are not supported yet."
            _ ->
              putStrLn "Building with the system-wide libsodium"
      }
