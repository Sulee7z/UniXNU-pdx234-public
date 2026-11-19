## SPDX-License-Identifier: BSD-2-Clause-Patent
[Defines]
  PLATFORM_NAME = pdx234
  PLATFORM_GUID = 0B21BBF5-5856-4F5A-B10A-35CDA6EF166C
  PLATFORM_VERSION = 0.1
  DSC_SPECIFICATION = 0x00010005
  OUTPUT_DIRECTORY = Build/pdx234Pkg
  SUPPORTED_ARCHITECTURES = AARCH64
  BUILD_TARGETS = RELEASE|DEBUG
  SKUID_IDENTIFIER = DEFAULT
  FLASH_DEFINITION = pdx234Pkg/pdx234.fdf
  SOC_TYPE = 0
  USE_CUSTOM_DISPLAY_DRIVER = 0
  # USB vendor dependency chain is opt-in; paired FDF includes identical INFs.
  DEFINE PDX234_VENDOR_USB = 0

!include KailuaPkg/KailuaPkg.dsc.inc

[BuildOptions]
  *_*_AARCH64_CC_FLAGS = -DPDX234_COMBO_HANDOFF=1

[PcdsFixedAtBuild]
  gArmTokenSpaceGuid.PcdSystemMemoryBase|0x80000000
  gArmPlatformTokenSpaceGuid.PcdCPUCoresStackBase|0xA760D000
  gArmPlatformTokenSpaceGuid.PcdCPUCorePrimaryStackSize|0x40000
  gSiliciumPkgTokenSpaceGuid.PcdSmbiosSystemManufacturer|"Sony"
  gSiliciumPkgTokenSpaceGuid.PcdSmbiosSystemModel|"PDX-234"
  gSiliciumPkgTokenSpaceGuid.PcdSmbiosSystemRetailModel|"XQ-DQ72"
  gSiliciumPkgTokenSpaceGuid.PcdSmbiosSystemRetailSku|"XQ-DQ72"
  gSiliciumPkgTokenSpaceGuid.PcdSmbiosSystemBoardModel|"PDX-234"
  # Sony OEM firmware provides 1096x2560 boot art. Initial geometry remains a candidate until GOP observation.
  gSiliciumPkgTokenSpaceGuid.PcdFrameBufferWidth|1096
  gSiliciumPkgTokenSpaceGuid.PcdFrameBufferHeight|2560
  gSiliciumPkgTokenSpaceGuid.PcdFrameBufferColorDepth|32
  gSiliciumPkgTokenSpaceGuid.PcdFrameBufferFontScale|2
  gSiliciumPkgTokenSpaceGuid.PcdFrameBufferDelay|0
  gQcomPkgTokenSpaceGuid.PcdPlatformType|"LA"
!if $(PDX234_VENDOR_USB) == 1
  gQcomPkgTokenSpaceGuid.PcdBuildXblHobs|TRUE
!else
  gQcomPkgTokenSpaceGuid.PcdBuildXblHobs|FALSE
!endif

[LibraryClasses]
  MemoryMapLib|pdx234Pkg/Library/MemoryMapLib/MemoryMapLib.inf
  PlatformSecLib|pdx234Pkg/Library/PlatformSecLib/PlatformSecLib.inf
  ConfigurationMapLib|pdx234Pkg/Library/ConfigurationMapLib/ConfigurationMapLib.inf
  UniXNULib|UniXNUPkg/Library/UniXNULib/UniXNULib.inf
  FdtLib|MdePkg/Library/BaseFdtLib/BaseFdtLib.inf

[Components]
!if $(PDX234_VENDOR_USB) == 1
!include pdx234Pkg/Include/UsbComponents.inc
!endif
  pdx234Pkg/Drivers/PdxConfigFsDxe/PdxConfigFsDxe.inf {
    <LibraryClasses>
      NULL|MdeModulePkg/Library/LzmaCustomDecompressLib/LzmaCustomDecompressLib.inf
      ExtractGuidedSectionLib|MdePkg/Library/DxeExtractGuidedSectionLib/DxeExtractGuidedSectionLib.inf
  }
  pdx234Pkg/Drivers/PdxKeyInputDxe/PdxKeyInputDxe.inf
  pdx234Pkg/Applications/PdxAndroidResume/PdxAndroidResume.inf
  UniXNUPkg/Application/UniXNU/UniXNU.inf
  UniXNUPkg/Driver/UniXNUDxe/UniXNUDxe.inf
  UniXNUPkg/Driver/UniXNURamDiskDxe/UniXNURamDiskDxe.inf
  DarwinBootPkg/Driver/DarwinBoot.inf {
    <BuildOptions>
      *_*_AARCH64_CC_FLAGS = -DPDX234_ENTRY_DRAM_BASE=0x880000000ULL -DPDX234_ENTRY_DRAM_BYTES=0x39d00000ULL
  }
