# PDX-234 firmware checkpoints

Use Sony's captured memory, FDT and peripheral inputs. The shared build and
verification workflow is documented at [UEFI integration](https://unixnu.com/porting/uefi-firmware)
and [bring-up](https://unixnu.com/porting/bring-up).

## DXE CapsuleArch omission (2026-11-07)

The default-menu candidate002 photo shows `Capsule Arch Protocol not present`
and `ASSERT [DxeCore] DxeMain.c(581)`, after PdxConfigFsDxe and PdxKeyInputDxe
initialized. It is not an AuthVariableLib assertion or an XNU failure.

Mu_Basecore `cfb93724a06ff86ff5ba971413368a7809ee42a5` requires all 13 entries
of `DxeProtocolNotify.c:mArchProtocols` before BDS. UEFI drivers without DEPEX
also wait for this check, explaining the undispatched disk/console modules.

SiliciumPkg.dsc.inc already selects the shared CapsuleRuntimeDxe and the null
CapsuleLib. Sony's FDF omitted the driver. Add its INF to FVMAIN, as the upstream
sheng DXE include does; retain the standard service implementation and assertions.
The null CapsuleLib rejects unsupported capsule images. No proprietary SCM marker
or authentication-library patch is needed to repair this omission.

Firmware005 (3 MiB, SHA256 `1199460f407282b25d7f1ed0e71c351c88ac1077f484a48a0ae238087321d2b1`)
builds successfully. Actual FD decompression finds all required provider modules.
Compared with firmware004, CapsuleRuntimeDxe is the only new FFS; every existing
leaf file is byte-identical. Only the enclosing compressed FV also changes.
The Android-preserving candidate003 passes container and selector host checks.

Hardware passage beyond DXE, the menu and Android-resume remain unverified.
The separate SCM warning in BDS is not this assertion; do not fake a protocol
to silence it. No device flash or reboot was performed by the agent.

## DarwinBoot registration before console connection (2026-11-07)

The next photo shows CapsuleRuntimeDxe, DiskIoDxe and FAT loading, confirming
the prior omission is repaired on device. DarwinBoot then asserts in
UefiLibPrint.c(63): its registration log calls Print while gST->ConOut is NULL.
This is still DXE dispatch, not a kernel handoff or iOS boot failure.

The consuming device recipe applies `patches/firmware/darwinboot-dxe-log.patch`
to the pinned DarwinBoot build copy. Only that early log changes to DebugLib.
Sony maps it to BaseDebugLibSerialPort/FrameBufferSerialPortLib, which does not
require the text console. Do not remove the Print assertion or force BDS to run
before the driver. Later Boot-path logging and all loader/PAC logic are unchanged.

Firmware007 and candidate004 build and pass host entry/container checks.
The corrected image has not run on hardware; menu and Android-resume remain
unverified. The canonical component checkout remains untouched.

## BDS form-browser dependency and QEMU gate (2026-11-07)

The next photo reaches BDS and asserts at BmDriverHealth.c(553). The default
nonzero PcdDriverHealthConfigureForm requires FormBrowser2 before checking
whether any controller needs repair. SetupBrowser was selected in the shared
DSC but not published in Sony's FV. Add the standard SetupBrowserDxe INF to
FVMAIN rather than deleting the assertion or fabricating a protocol.

Firmware008 builds with the browser included; five actual-container regression
cases pass. No handset image is packed or offered. The user now requires a
real QEMU SpringBoard boot before any new handset flash request.

The common UniXNU QEMU suite passes 20 invocations on virt/AAVMF after correcting
the stale built-in Tools entry count in the test copy. These are UEFI/payload
fixtures, not Sony hardware or an iOS boot. Native arm64e compilation, target
OS/SystemOS/Data and QEMU storage/display remain prerequisites.

## Android-resume cache API assertion (2026-11-08)

The user's interim menu005 test photo reaches PdxAndroidResume and stops at
ArmCacheMaintenanceLib.c(90). This is WriteBackInvalidateDataCache's deliberate
ASSERT(FALSE), after successful ExitBootServices in the source path. The next
InvalidateInstructionCache API also asserts in the selected library.

Use implemented WriteBackDataCacheRange on the retained Image and complete,
bounded FDT, followed by ArmLib's implemented ArmInvalidateInstructionCache.
Linux's ARM64 entry contract requires Image clean-to-PoC by VA. Do not add a
set/way sweep, remove assertions or replace the original Android kernel.
Entry/MMU assembly, wrapper, config filesystem and board memory remain unchanged.

Firmware009/candidate006 build and final-container checks pass. Seven actual-C
and cache-library regression groups pass with hardware/Boot Services modeled;
eight wrapper selector cases pass. The old compiled source reproduces the
assertion. Only AndroidResume changes functionally; PcdDxe changes only its RSDS
debug identifier. Hardware Android return remains unverified. No handset
operation was performed. See the device's evidence/android-resume-cache-fix-006.json.

## Official Linux/EFI-stub path (2026-11-08)

The user's next photo shows a synchronous exception at 0xc7058678 and a recursive
CPU-context dump in the manual-return path. The lost register dump does not
establish a precise cause. The user explicitly requested the documented Linux path.

PdxConfigFsDxe now publishes a type=linux entry and read-only Image, original FDT
and bootloader-assembled initrd files. It preserves /chosen/bootargs, pins inherited
input pages and supplies a real volume device path. Standard UniXNU Boot.c and
Inject.c remain unchanged; the original kernel EFI stub handles the CPU handoff.
The historical AndroidResume app remains unselected, not silently patched again.

Firmware010 builds. The actual new filesystem C plus unchanged captured GKI boots
through standard UniXNU and LoadFile2 to a real Linux PID1 under QEMU virt/AAVMF.
The virtual test uses its own small /init, not Android services/UI or Sony hardware.
Two failed fixtures are retained: an AMBA-probe fault and insufficient writable DTB
slack. Their fixture-only corrections do not change Sony DT or the phone kernel.
Candidate007 preserves the Android bytes and external dependencies. No handset
operation was performed. See evidence/official-linux-path-007.json in the device repo.

## Current route: volume-up gates iOS menu (2026-11-08)

The user paused Android-from-UEFI and selected normal direct Android plus a held
volume-up iOS menu. BootShim now tests Sony PON PPID0x013/RESIN bit6. Every absent
key/controller error/timeout defaults to Android, before any firmware copy or
cache/MMU transition. Volume-down GPIO6 is no longer a boot selector.

The current config FS contains no Android entry or Android image/initrd files.
It is a small static iOS-menu config, without ramdisk parsing/copying/pinning.
The genuine iPhone14 payload is not ready: its entry remains disabled, leaving
reset/shutdown actions visible. Do not enable a nonexistent kernel to pretend the
iOS goal is complete. Historical Linux-path sources/tests remain pinned in Git.

Firmware011 and candidate008 build. Eleven compiled-selector simulations verify
no-key/power-only/down-only/error paths to Android and volume-up paths to UEFI,
with original x0-x3/SP retained on Android. Three menu-policy checks and actual
config/FD/Android byte checks pass. No handset operation or iOS boot is established.

## Disabled default entry correction and iOS delivery gate

The disabled ios27 entry cannot be named as the placeholder default: UniXNU
rejects a default absent from its enabled-entry list. Omit default while payload
construction is pending; do not enable nonexistent kernel files to hide the error.
The corrected source passes menu-policy tests. No new handset image is packed.
The user requires genuine iPhone14 SpringBoard process/framebuffer evidence in
QEMU before flash delivery. Reviewed Sheng reuse does not transfer J820 ABI
addresses, its contiguous RAM geometry or its partition layout to Sony/D27.
