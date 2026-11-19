// SPDX-License-Identifier: BSD-2-Clause-Patent
#include <AsmMacroLib.h>
ASM_FUNC(PdxCurrentEl)
  mrs x0, CurrentEL
  ret
ASM_FUNC(PdxAndroidEnter)
  mov x18, x0
  mov x20, x1
  msr daifset, #15
  dsb sy
  mrs x4, sctlr_el1
  bic x4, x4, #1
  bic x4, x4, #4
  bic x4, x4, #0x1000
  msr sctlr_el1, x4
  isb
  tlbi vmalle1
  dsb sy
  isb
  mov x0, x20
  mov x1, xzr
  mov x2, xzr
  mov x3, xzr
  br x18
