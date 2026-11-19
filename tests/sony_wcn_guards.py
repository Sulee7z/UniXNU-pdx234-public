"""Execute the generated production startup gates without kernel/MMIO services.

Only entry-point bodies are extracted. Kernel thread/power/firmware services are
instrumented boundaries, not a replacement driver or success transport.
"""
from pathlib import Path


def body(text: str, signature: str) -> str:
    start = text.index(signature)
    opening = text.index("{", start)
    depth = 1
    at = opening + 1
    while depth:
        if text[at] == "{":
            depth += 1
        elif text[at] == "}":
            depth -= 1
        at += 1
    return text[start:at]


def source(build: Path) -> str:
    wifi = body((build / "source/WifiProbe.cpp").read_text(), 'extern "C" void native_sony_wifi_start(void)')
    bt = body((build / "source/BluetoothProbe.cpp").read_text(), 'extern "C" void native_sony_bluetooth_start(void)')
    return r'''
#include <cassert>
#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <cstring>
using thread_t=void *;
constexpr int KERN_SUCCESS=0;
uint32_t native_wifi_stats[29];uint64_t native_bluetooth_stats[32];
uint8_t dma[1];uint8_t *native_ufs_extra_va=dma;
uint32_t native_ufs_extra_stream=0x1401,native_ufs_extra_bytes=32u*1024*1024;
char *native_bluetooth_boot_text;
struct {uint32_t started;unsigned log;} bt;
unsigned wifi_level,bt_level,threads,addresses,thread_result;
int platform_error,msi_error,wifi_error,bt_error;
bool PE_parse_boot_argn(const char *name,void *data,size_t n) {
    unsigned value=!strcmp(name,"wifi")?wifi_level:!strcmp(name,"bluetooth")?bt_level:0;
    assert(n==4);memcpy(data,&value,4);return true;
}
int sony_wcn_platform_ready(){return platform_error;}
int sony_wcn_platform_wifi_ready(){return msi_error;}
int sony_wcn_platform_bluetooth_ready(){return msi_error;}
int sony_wcn_wifi_inputs_ready(){return wifi_error;}
int sony_wcn_bluetooth_inputs_ready(){return bt_error;}
void wifiThread(void *,int){} void worker(void *,int){} void processWatch(void *,int){}
int kernel_thread_start(void(*)(void *,int),void *,thread_t *t){++threads;*t=nullptr;return thread_result;}
void thread_deallocate(thread_t){}
void *IOMallocData(size_t){assert(false);return nullptr;}
bool address(){++addresses;return true;}
''' + wifi + "\n" + bt + r'''
int main(){
    // Missing shared provider: no thread, GPIO reset, mapping, publication or power.
    wifi_level=5;bt_level=1;platform_error=ENXIO;
    native_sony_wifi_start();native_sony_bluetooth_start();
    assert(!threads && !addresses && native_wifi_stats[0]==uint32_t(-ENXIO));
    assert(native_bluetooth_stats[1]==uint64_t(int64_t(-ENXIO)));
    platform_error=0;msi_error=ENXIO;
    native_sony_wifi_start();assert(!threads && native_wifi_stats[0]==uint32_t(-ENXIO));
    msi_error=0;wifi_error=ENOENT;bt_error=ENOENT;
    native_sony_wifi_start();native_sony_bluetooth_start();
    assert(!threads && !addresses && native_wifi_stats[0]==uint32_t(-ENOENT));
    assert(native_bluetooth_stats[1]==uint64_t(int64_t(-ENOENT)));
    wifi_error=0;native_ufs_extra_stream=0xa3;
    native_sony_wifi_start();assert(!threads && native_wifi_stats[0]==uint32_t(-ENXIO));
    native_ufs_extra_stream=0x1401;
    // Invalid stages never silently select a controller/MHI experiment.
    wifi_level=3;bt_level=2;native_sony_wifi_start();native_sony_bluetooth_start();
    assert(!threads && !addresses && native_wifi_stats[0]==uint32_t(-EINVAL));
    assert(native_bluetooth_stats[1]==uint64_t(int64_t(-EINVAL)));
    // A failed thread creation permits retry; accepted startup is once-only.
    wifi_level=5;bt_level=1;wifi_error=bt_error=0;thread_result=1;
    native_sony_wifi_start();native_sony_bluetooth_start();assert(threads==2);
    thread_result=0;native_sony_wifi_start();native_sony_bluetooth_start();assert(threads==4);
    native_sony_wifi_start();native_sony_bluetooth_start();assert(threads==4);
    puts("PASS generated production gates: absent provider/ITS/firmware, invalid stages, thread failure retry, once-only startup");
}
'''
