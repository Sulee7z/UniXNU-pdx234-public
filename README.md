# UniXNU for Sony Xperia 1 V (PDX234)

This device repository contains the Sony Xperia 1 V XQ-DQ72 adaptations for the UniXNU SM8550 port. The local PDX071 image uses the iPhone14,7 iOS 27.0.1 (24A446) profile and the XNU 12377.121.6 source route. See the [device repository guide](https://unixnu.com/porting/device-repository) and [porting record](porting.toml).

The PDX070 handset log records a Wi-Fi failure before MHI and an OLED resource failure before DSI commands. The Bluetooth controller started. Active discovery remains unresolved. PDX071 includes changes to the Wi-Fi SMMU check and the OLED readiness wait, with separate Bluetooth discovery counters. PDX071 has passed strict prelink and Linux and Windows image readback. See the [PDX070 runtime record](evidence/d27-platform070-handset-readback.json) and [PDX071 host record](evidence/d27-platform071-delivery.json).

## Build status

Use the pinned `UniXNU/UniXNU` revision `563595abedfdfa413ad583b66b6176d82007e633` beside this repository. Copy `profiles/ios-27.0.1-24A446-iphone14` into `UniXNU/profiles/os/` in a dedicated builder checkout. The resolver then accepts the checked-in Sony bootstrap configuration. Run `bash scripts/package.sh --check --no-deps` with the configured SoC and source dependencies available. `scripts/package.sh` is the official template. See the [packaging guide](https://unixnu.com/porting/packaging).

`board.toml` currently selects the bootstrap configuration. The PDX071 kernel layers are in `ci/platform069/`, `drivers/`, and `scripts/ci/`. Its qualified local build uses explicit archive selection, an OS-specific prelink profile, a retained Sony firmware image and Sony’s Android-preserving packer. The standard clean-checkout build still needs integration of these local steps and reduction of the 1016-byte command line to the standard 999-byte limit. The GitHub workflow validates the record and packaging preflight while this integration is underway.

The Sony UEFI source overlay is in `firmware/sony-overlay/`. The upstream UEFI tree, prepared Sony firmware files, original iOS boot inputs and build-local inputs are described in [proprietary-files.txt](proprietary-files.txt).

`package/selected071/` contains 135 exact source exports selected by the current
link plan, including the native XNU overlays, Sony radio and OLED owners, and
userspace adapters. Its source manifest records hashes and effective component
pins. These are the open-source inputs used by the local candidate. Proprietary
inputs and local replay artifacts are kept outside this public repository.

## Selected sources and license

The native sources retain Apple's notices and `package/selected071/APPLE_LICENSE`.
Board code retains UniXNU's BSD-2-Clause-Patent notices. Imported components keep
their own source license. The repository-level license does not replace those
notices. Upstream component selection and actual local exports are recorded
separately because some local builds use newer component pins than the root
bootstrap resolver.

Public CI validates the exact selected-source hashes and the tests that use
public inputs. Two integration suites report their missing private IPSW and
handset fixtures as skipped. They execute with all assertions in the local
handoff environment. CI does not claim a hardware result or a full image build.
