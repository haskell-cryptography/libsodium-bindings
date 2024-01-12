module Main where

import Control.Monad
import Debug.Trace
import Distribution.Simple
import Distribution.Simple.Setup
import Distribution.System
import Distribution.Types.Flag
import Distribution.Types.LocalBuildInfo
import System.Directory (copyFile, doesFileExist, renameFile, withCurrentDirectory, getCurrentDirectory, createDirectoryIfMissing)
import System.FilePath ((<.>), (</>))
import Data.Maybe
import System.Process (system)
import qualified Distribution.PackageDescription as PD

main =
  defaultMainWithHooks $
    simpleUserHooks
      { confHook = customConfHook
      , postConf = customPostConfHook
      }

customConfHook
  :: (PD.GenericPackageDescription, PD.HookedBuildInfo)
  -> ConfigFlags
  -> IO LocalBuildInfo
customConfHook (description, buildInfo) flags = do
  localBuildInfo <- confHook simpleUserHooks (description, buildInfo) flags
  let packageDescription = localPkgDescr localBuildInfo
      library = fromJust $ PD.library packageDescription
      libraryBuildInfo = PD.libBuildInfo library
  dir <- getCurrentDirectory
  pure
    localBuildInfo
      { localPkgDescr =
          packageDescription
            { PD.library =
                Just $
                  library
                    { PD.libBuildInfo =
                        libraryBuildInfo
                          { PD.extraLibDirs =
                              (dir </> ".libsodium" </> show buildOS </> show buildArch)
                                : PD.extraLibDirs libraryBuildInfo
                          }
                    }
            }
      }

customPostConfHook :: Args -> ConfigFlags -> p2 -> LocalBuildInfo -> IO ()
customPostConfHook _args configFlags _packageDescription localBuildInfo =
  case lookupFlagAssignment (mkFlagName "bundled-libsodium") (configConfigurationsFlags configFlags) of
    Just True -> do
      putStrLn "Building with the bundled libsodium 1.0.18-stable"
      dir <- getCurrentDirectory
      let destinationPath = traceId $ buildDir localBuildInfo </> "libCsodium" <.> "a"
      let wellKnownPath = traceId $ dir </> ".libsodium" </> show buildOS <> "-" <> show buildArch
      case (buildOS, buildArch) of
        (Windows, X86_64) -> do
          -- Cabal, and indeed, GHC, don't understand the .lib extension on
          -- Windows, so we have the same name everywhere.
          copyFile ("binaries" </> "x86_64-windows" </> "libsodium" <.> "a") destinationPath
        (Linux, X86_64) -> do
          copyFile ("binaries" </> "x86_64-linux" </> "libsodium" <.> "a") destinationPath
          createDirectoryIfMissing True wellKnownPath
          copyFile ("binaries" </> "x86_64-linux" </> "libsodium" <.> "a") (wellKnownPath </> "libCsodium" <.> "a")
        (FreeBSD, X86_64) -> do
          copyFile ("binaries" </> "x86_64-freebsd" </> "libsodium" <.> "a") destinationPath
        (os, arch) ->
          putStrLn $ "Static libsodium builds for " <> show arch <> "-" <> show os <> " are not supported yet."
    _ ->
      putStrLn "Building with the system-wide libsodium"
