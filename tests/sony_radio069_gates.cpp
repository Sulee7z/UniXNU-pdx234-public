/* SPDX-License-Identifier: BSD-2-Clause-Patent */
// Verbatim worker prefixes end at their first post-qualification operation.
// A sentinel marks reaching that boundary. No radio hardware is modeled here.
#include "sony_radio069_host.h"
using wait_result_t=int;
static uint32_t native_wifi_stats[29];
static uint64_t native_bluetooth_stats[32];
static unsigned sleeps,entered_power_path,configured_variant=1,install_after;
static unsigned bt_boot_reports;
static int bt_boot_error;
static void qbt_transport_boot_result(int error,const char *firmware,uint32_t speed) {
    CHECK(error>0 && !firmware && !speed);++bt_boot_reports;bt_boot_error=error;
}
static void *current_thread(){return nullptr;}
static void thread_set_thread_name(void *,const char *){}
static void native_wifi_logf(int,const char *,...){}
static bool PE_parse_boot_argn(const char *name,void *value,size_t bytes) {
    CHECK(!strcmp(name,"wifi-fw") && bytes==sizeof(configured_variant));
    memcpy(value,&configured_variant,bytes);return true;
}
static void IOSleep(unsigned ms) {
    CHECK(ms==500);sleeps++;
    if(install_after && sleeps==install_after)native_gpu_addon_stage=1;
}
static void host_power_boundary(){entered_power_path++;}
#include "worker-gates.inc"
static void reset() {
    host_reset();sleeps=entered_power_path=install_after=0;configured_variant=1;
    bt_boot_reports=0;bt_boot_error=0;
    memset(native_wifi_stats,0,sizeof(native_wifi_stats));
    memset(native_bluetooth_stats,0,sizeof(native_bluetooth_stats));
}
static void run_wifi(){wifiThread(reinterpret_cast<void *>(uintptr_t(5)),0);}
static void run_bt(){worker(nullptr,0);}
static void cases(void (*run)(),bool wifi) {
    reset();native_gpu_addon_stage=0;run();
    CHECK(sleeps==240 && !entered_power_path && !host_opens && !host_live_allocations);
    if(wifi)CHECK((int32_t)native_wifi_stats[0]==-EAGAIN);
    else CHECK(native_bluetooth_stats[0]==3 && (int64_t)native_bluetooth_stats[1]==-EAGAIN && bt_boot_reports==1 && bt_boot_error==EAGAIN);
    reset();native_gpu_addon_stage=0;install_after=3;run();
    CHECK(sleeps==3 && entered_power_path==1 && !host_live_allocations);
    reset();host_fault.missing=wifi?"sony-regdb.bin":"qca/hmtnv20.bin";run();
    CHECK(!entered_power_path && !sleeps && !host_live_allocations);
    if(!wifi)CHECK(bt_boot_reports==1 && bt_boot_error==ENOENT);
    reset();host_fault.tamper=1;run();CHECK(!entered_power_path && !sleeps && !host_live_allocations);
    reset();host_fault.getattr_error=EACCES;run();CHECK(!entered_power_path && !sleeps && !host_live_allocations);
    reset();host_fault.fail_allocation=1;run();CHECK(!entered_power_path && !sleeps && !host_live_allocations);
    reset();host_fault.resid=1;run();CHECK(!entered_power_path && !sleeps && !host_live_allocations);
    reset();run();CHECK(entered_power_path==1 && !sleeps && !host_live_allocations && !bt_boot_reports);
}
int main() {
    host_init();cases(run_wifi,true);cases(run_bt,false);
    reset();configured_variant=2;run_wifi();CHECK(!entered_power_path && !host_opens && (int32_t)native_wifi_stats[0]==-ENOTSUP);
    host_fini();puts("{\"passed\":true,\"verbatim_worker_prefix_cases\":17,\"hardware_modeled\":false}");
}
