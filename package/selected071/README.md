# Effective PDX071 source

These exports preserve the open-source translation units selected by the PDX071
local linker plan. `followup071/` replaces the corresponding `radio/` and `oled/`
files. `native/` contains XNU and board overlays. Each source retains its original
license and notice. `source-manifest.json` records file hashes and upstream pins.
Generated firmware contents, Apple userland binaries, device platform seeds,
signing keys and original OS images are local build inputs.

The sources under `drivers/`, `ci/` and `scripts/ci/` describe the construction
and validation of these exports. The ordinary board resolver still selects the
bootstrap configuration; the full PDX071 clean-checkout release migration is
incomplete. The local handoff includes its incremental object closure separately.
