{
  description = "Encrypt and decrypt secrets using SSH agent keys";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    rust-overlay.url = "github:oxalica/rust-overlay";
    rust-overlay.inputs.nixpkgs.follows = "nixpkgs";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, rust-overlay, flake-utils, ... }:
    let
      cargoToml = builtins.fromTOML (builtins.readFile ./Cargo.toml);

      # Overlay that adds ssh-tresor to pkgs
      overlay = final: prev: {
        ssh-tresor = final.rustPlatform.buildRustPackage {
          pname = cargoToml.package.name;
          version = cargoToml.package.version;

          src = self;

          cargoLock.lockFile = ./Cargo.lock;

          # Integration tests require ssh-agent, only run unit tests in nix build
          cargoTestFlags = [ "--lib" ];

          meta = with final.lib; {
            description = "Encrypt and decrypt secrets using SSH agent keys";
            homepage = "https://github.com/haraldh/ssh-tresor";
            license = with licenses; [ mit asl20 ];
            maintainers = [ ];
            mainProgram = "ssh-tresor";
          };
        };
      };
    in
    {
      # Overlay for other flakes to use
      overlays.default = overlay;

    } // flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = import nixpkgs {
          inherit system;
          overlays = [ (import rust-overlay) overlay ];
        };
        rustToolchain = pkgs.rust-bin.stable.latest.default.override {
          extensions = [ "rust-src" "rust-analyzer" ];
        };
      in
      {
        packages = {
          ssh-tresor = pkgs.ssh-tresor;
          default = pkgs.ssh-tresor;
        };

        devShells.default = pkgs.mkShell {
          buildInputs = with pkgs; [
            rustToolchain
            pkg-config
            openssl
          ];

          RUST_BACKTRACE = 1;
        };
      }
    );
}
