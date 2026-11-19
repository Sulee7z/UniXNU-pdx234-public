/* SPDX-License-Identifier: BSD-2-Clause-Patent */
/* Read selected native XNU declarations; never infer core online state from OPPs. */
#include <stdint.h>
#include <kern/processor.h>
#include <arm/cpu_data_internal.h>
extern void IOLog(const char *,...);
extern volatile uint32_t armcpu_smp_requested,armcpu_smp_running;
extern volatile uint32_t armcpu_smp_step[8],armcpu_smp_fail[8];
extern volatile int32_t armcpu_smp_psci_rc[8];
extern volatile uint32_t armcpu_core_timer[8],armcpu_core_sgi[8];
volatile uint32_t native_sony_cpu_present_mask,native_sony_cpu_running_mask,native_sony_cpu_schedulable_mask;
static uint32_t previous_timer[8],previous_ipi[8];

void native_sony_cpu_snapshot(void) {
    uint32_t present=0,running=0,schedulable=0;
    for(unsigned cpu=0;cpu<8 && cpu<MAX_CPUS;++cpu) {
        cpu_data_t *data=CpuDataEntries[cpu].cpu_data_vaddr;
        processor_t processor=processor_array[cpu];
        const unsigned state=processor?(unsigned)__atomic_load_n(&processor->state,__ATOMIC_RELAXED):~0u;
        const unsigned alive=data?__atomic_load_n(&data->cpu_running,__ATOMIC_RELAXED):0;
        const uint32_t timer=__atomic_load_n(&armcpu_core_timer[cpu],__ATOMIC_RELAXED);
        const uint32_t ipi=__atomic_load_n(&armcpu_core_sgi[cpu],__ATOMIC_RELAXED);
        if(data && processor)present|=1u<<cpu;
        if(alive)running|=1u<<cpu;
        if(state==PROCESSOR_IDLE || state==PROCESSOR_DISPATCHING || state==PROCESSOR_RUNNING)schedulable|=1u<<cpu;
        IOLog("[pdx-cpu] core=%u present=%u running=%u state=%u step=%u fail=%u psci=%d timer=%u delta=%u ipi=%u delta=%u\n",
            cpu,data && processor,alive,state,armcpu_smp_step[cpu],armcpu_smp_fail[cpu],armcpu_smp_psci_rc[cpu],
            timer,timer-previous_timer[cpu],ipi,ipi-previous_ipi[cpu]);
        previous_timer[cpu]=timer;previous_ipi[cpu]=ipi;
    }
    native_sony_cpu_present_mask=present;native_sony_cpu_running_mask=running;native_sony_cpu_schedulable_mask=schedulable;
    IOLog("[pdx-cpu-summary] registered=%u secondary-requested=%u secondary-running=%u present=%02x running=%02x schedulable=%02x states=4idle/5dispatch/6running\n",
        processor_count,armcpu_smp_requested,armcpu_smp_running,present,running,schedulable);
}
