{
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs";
    flake-utils.url = "github:numtide/flake-utils";
    flake-compat = {
      url = "github:edolstra/flake-compat";
      flake = false;
    };
    pre-commit-hooks.url = "github:cachix/pre-commit-hooks.nix";
    gitignore = {
      url = "github:hercules-ci/gitignore.nix";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs = { self, nixpkgs, flake-utils, pre-commit-hooks, gitignore, ... }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        inherit (gitignore.lib) gitignoreSource;

        overlay = self: super: {
          haskell = super.haskell // {
            packages = super.haskell.packages // {
              ghc945 = super.haskell.packages.ghc945.override (old: {
                overrides =
                  let
                    oldOverrides = old.overrides or (_: _: { });

                    manualOverrides = haskPkgsNew: haskPkgsOld:
                      {
                        libsodium-bindings =
                          haskPkgsOld.libsodium-bindings.override {
                            libsodium = super.libsodium;
                          };
                      };

                    packageSources =
                      self.haskell.lib.packageSourceOverrides {
                        libsodium-bindings = gitignoreSource ./libsodium-bindings;
                        sel = gitignoreSource ./sel;
                      };

                  in
                  self.lib.fold self.lib.composeExtensions oldOverrides [
                    packageSources
                    manualOverrides
                  ];
              });
            };
          };
        };

        config.allowBroken = true;
        pkgs = import nixpkgs { inherit config system; overlays = [ overlay ]; };
        defaultHaskellPackages = pkgs.haskellPackages;
        myHaskellPackages = pkgs.haskell.packages.ghc945;
      in
      {
        checks = {
          pre-commit-check = pre-commit-hooks.lib.${system}.run {
            src = ./.;
            hooks = {
              nixpkgs-fmt.enable = true;
              fourmolu.enable = true;
              cabal-fmt.enable = true;
              hlint.enable = true;
            };
          };
        };

        packages = {
          inherit (myHaskellPackages) libsodium-bindings sel;
        };

        devShells.default = myHaskellPackages.shellFor {
          inherit (self.checks.${system}.pre-commit-check) shellHook;

          packages = packages: with packages; [
            libsodium-bindings
            sel
          ];

          buildInputs = [
            defaultHaskellPackages.cabal-install
            myHaskellPackages.haskell-language-server
            pkgs.nixpkgs-fmt
            defaultHaskellPackages.cabal-fmt
            defaultHaskellPackages.fourmolu
            defaultHaskellPackages.hlint
          ];
        };
      }
    );
}
