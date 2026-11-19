/* Sony PDX234: inherited SM8550 controller state, no reset/control ownership.
 * Captured live.dtb 20261110T051320Z: DWC3 a600000, SID40, coherent DMA,
 * INTID165, GCC100000, apps SMMU15000000; Kalama GCC offsets from Sm8550.h.
 * Runtime qualification must prove power/clock/PHY/role and stopped old DMA.
 */
#include "soc/Sm8550.h"
#undef QUD_SOC_NAME
#define QUD_SOC_NAME "pdx234-sm8550-inherited"
#undef QUD_PSCI_SMC_RESET
#define QUD_PSCI_SMC_RESET 0
#undef QUD_USB_SERIAL
#define QUD_USB_SERIAL "PDX234XnuLog"
#undef QUD_USB_PRODUCT
#define QUD_USB_PRODUCT "Sony PDX234 XNU Log"
/* Sony live DT: snps,disable-clk-gating. Linux dwc3_phy_setup also
 * clears USB3 SUSPENDENABLE before the device reset synchronizes clocks. */
#define QUD_USB_RESET_CLOCK_PREP 1
/* The native CDC backend advertises HS/FS only. Select the documented
 * Qualcomm UTMI substitute instead of depending on a running SS PIPE PHY. */
#define QUD_USB_HS_UTMI_CLOCK 1
#define QUD_QSCRATCH_GENERAL_CFG_OFFSET 0xf8808u
