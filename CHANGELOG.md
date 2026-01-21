# Changelog

## [0.4.0](https://github.com/haraldh/ssh-tresor/compare/ssh-tresor-v0.3.0...ssh-tresor-v0.4.0) (2026-01-21)


### Features

* add --all flag to add-key command ([94a4e54](https://github.com/haraldh/ssh-tresor/commit/94a4e54450b92fb2869577499f0862a1e7471ceb))
* add --in-place flag to add-key and remove-key ([91fabd4](https://github.com/haraldh/ssh-tresor/commit/91fabd457d265be7768d71ecdc324b5c9ad97580))
* add overlay and package outputs to flake ([0cd6444](https://github.com/haraldh/ssh-tresor/commit/0cd6444b7a3ce32b184b78b1729a32c94a633e04))
* try security keys last during decrypt ([09f629e](https://github.com/haraldh/ssh-tresor/commit/09f629ea3286e123829d701b2b127722862929b3))

## [0.3.0](https://github.com/haraldh/ssh-tresor/compare/ssh-tresor-v0.2.0...ssh-tresor-v0.3.0) (2026-01-21)


### ⚠ BREAKING CHANGES

* v3 format uses HKDF key derivation and is not compatible with v2. Existing tresors cannot be decrypted.

### Features

* add release-please GitHub Action ([ecb8de8](https://github.com/haraldh/ssh-tresor/commit/ecb8de8b36d93788287a949078ee08042f2a76e3))
* security improvements and v3 format ([#6](https://github.com/haraldh/ssh-tresor/issues/6)) ([de0b8dc](https://github.com/haraldh/ssh-tresor/commit/de0b8dcd59196afebfa38739be3b6d76a5ac7a46))

## [0.2.0](https://github.com/haraldh/ssh-tresor/compare/v0.1.1...v0.2.0) (2026-01-20)


### Features

* add release-please GitHub Action ([ecb8de8](https://github.com/haraldh/ssh-tresor/commit/ecb8de8b36d93788287a949078ee08042f2a76e3))
