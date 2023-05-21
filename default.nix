{ compiler ? "ghc944" }:

let
  sources = import ./nix/sources.nix;

  inherit (import sources."gitignore.nix" { inherit (pkgs) lib; }) gitignoreSource;

  nixpkgs = sources.nixpkgs;

  config = {
    allowBroken = true;
  };

  overlay = self: super: {
    haskell = super.haskell // {
      packages = super.haskell.packages // {
        "${compiler}" = super.haskell.packages."${compiler}".override (old: {
          overrides =
            let
              packageSources =
                self.haskell.lib.packageSourceOverrides {
                  libsodium-bindings = gitignoreSource ./libsodium-bindings;
                  sel = gitignoreSource ./sel;
                };

              manualOverrides = haskPkgsNew: haskPkgsOld:
                {
                  libsodium-bindings =
                    haskPkgsOld.libsodium-bindings.override {
                      libsodium = super.libsodium;
                    };

                  # TODO: this seems unused
                  ghcid = self.haskell.lib.overrideCabal
                    (self.haskell.lib.dontCheck haskPkgsOld.ghcid)
                    (old: {
                      testToolDepends = [ super.libsodium ];
                    });
                };

              default = old.overrides or (_: _: { });

            in
            self.lib.fold self.lib.composeExtensions default [
              packageSources
              manualOverrides
            ];
        });
      };
    };
  };

  pkgs = import nixpkgs {
    inherit config;
    overlays = [ overlay ];
  };

in
{
  inherit (pkgs.haskell.packages."${compiler}") libsodium-bindings sel;
  shell =
    (pkgs.haskell.packages."${compiler}".sel).env.overrideAttrs (
      old: with pkgs.haskell.packages."${compiler}"; {
        nativeBuildInputs = old.nativeBuildInputs ++ [
          pkgs.libsodium
          cabal-install # TODO: cabal repl libsodium-bindings fails.
          fourmolu
          cabal-fmt
          ghcid # TODO: ghcid -c "cabal repl libsodium-bindings" fails
          haskell-language-server
        ];
      }
    );
}
