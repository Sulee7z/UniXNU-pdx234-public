"""Run the actual firmware glue against host boot-service callbacks."""
from pathlib import Path
import subprocess
import tempfile
import unittest

SOURCE=Path(__file__).resolve().parents[2]/'uefi-pdx234/Platforms/Sony/pdx234Pkg/Drivers/PdxUsbPrepareDxe/PdxUsbPrepare.c'

class UsbPrepare(unittest.TestCase):
    def test_event_order_and_failures(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp)
            for header in ['Uefi.h','Guid/EventGroup.h','Protocol/UsbFunctionIo.h',
                           'Library/UefiBootServicesTableLib.h','Library/UefiLib.h',
                           'Library/MemoryAllocationLib.h','Library/DebugLib.h']:
                p=root/header;p.parent.mkdir(parents=True,exist_ok=True);p.write_text('')
            pre=r'''
#include <stdint.h>
#include <stdlib.h>
#include <assert.h>
#define STATIC static
#define VOID void
#define EFIAPI
#define TRUE 1
#define FALSE 0
#define DEBUG(x) ((void)0)
#define DEBUG_ERROR 1
#define EFI_ERROR(x) ((x)!=0)
#define EVT_NOTIFY_SIGNAL 0x200
#define EVT_TIMER 0x80000000
#define TPL_CALLBACK 8
#define TimerRelative 2
#define ByProtocol 2
typedef unsigned long UINTN;
typedef unsigned int UINT32;
typedef int BOOLEAN;
typedef int EFI_STATUS;
typedef void *EFI_EVENT;
typedef void *EFI_HANDLE;
typedef void EFI_SYSTEM_TABLE;
typedef struct {uint32_t a;uint16_t b,c;uint8_t d[8];} EFI_GUID;
typedef void (*NOTIFY)(EFI_EVENT,void*);
typedef struct USB {UINT32 Revision;EFI_STATUS (*StartController)(struct USB*);} EFI_USBFN_IO_PROTOCOL;
static EFI_GUID gEfiEventReadyToBootGuid,gEfiUsbFunctionIoProtocolGuid;
static NOTIFY ready,timer;
static unsigned signals,starts,phase;
static int failure;
static EFI_STATUS create_ex(UINT32 t,UINTN tpl,NOTIFY fn,void *ctx,EFI_GUID *g,EFI_EVENT *e) {
 (void)t;(void)tpl;(void)ctx;
 if(failure==1)return 1;
 if(g==&gEfiEventReadyToBootGuid)ready=fn;
 *e=(void*)1;return 0;
}
static EFI_STATUS signal(EFI_EVENT e){(void)e;++signals;phase=1;return failure==2;}
static EFI_STATUS close_event(EFI_EVENT e){(void)e;return 0;}
static EFI_STATUS create(UINT32 t,UINTN tpl,NOTIFY fn,void* c,EFI_EVENT *e){
 (void)t;(void)tpl;(void)c;assert(phase==1);timer=fn;*e=(void*)2;return failure==3;
}
static EFI_STATUS set_timer(EFI_EVENT e,int mode,uint64_t ticks){
 (void)e;assert(mode==2 && ticks==100000);return failure==4;
}
static EFI_STATUS start(EFI_USBFN_IO_PROTOCOL *u){(void)u;assert(phase==2);++starts;return 0;}
static EFI_USBFN_IO_PROTOCOL usb={0x10001,start};
static EFI_STATUS locate(int type,EFI_GUID*g,void*c,UINTN*n,EFI_HANDLE**h){
 (void)type;(void)g;(void)c;assert(phase==2);if(failure==5)return 1;
 *n=1;*h=malloc(sizeof(void*));**h=(void*)3;return 0;
}
static EFI_STATUS handle(EFI_HANDLE h,EFI_GUID*g,void**u){(void)h;(void)g;*u=&usb;return failure==6;}
static void FreePool(void*p){free(p);}
static struct {EFI_STATUS (*CreateEventEx)(UINT32,UINTN,NOTIFY,void*,EFI_GUID*,EFI_EVENT*);
 EFI_STATUS (*SignalEvent)(EFI_EVENT);EFI_STATUS (*CloseEvent)(EFI_EVENT);
 EFI_STATUS (*LocateHandleBuffer)(int,EFI_GUID*,void*,UINTN*,EFI_HANDLE**);
 EFI_STATUS (*HandleProtocol)(EFI_HANDLE,EFI_GUID*,void**);
 EFI_STATUS (*CreateEvent)(UINT32,UINTN,NOTIFY,void*,EFI_EVENT*);
 EFI_STATUS (*SetTimer)(EFI_EVENT,int,uint64_t);
} services={create_ex,signal,close_event,locate,handle,create,set_timer},*gBS=&services;
'''
            post=r'''
int main(void){
 for(failure=0;failure<=6;++failure){
  mAttempted=0;ready=timer=0;signals=starts=phase=0;
  int result=PdxUsbPrepareEntry(0,0);
  if(failure==1){assert(result);continue;}
  assert(!result && ready);ready(0,0);assert(!starts);
  ready(0,0);assert(signals==1);
  if(failure==2 || failure==3 || failure==4)continue;
  assert(timer);phase=2;timer(0,0);
  assert(starts==(failure==0?1u:0u));
 }
 return 0;
}
'''
            source=root/'test.c';source.write_text(pre+'\n#include "'+SOURCE.as_posix()+'"\n'+post)
            subprocess.run(['clang','-std=c11','-Wall','-Wextra','-Werror','-fsanitize=address,undefined',
                            '-I',str(root),str(source),'-o',str(root/'test')],check=True,capture_output=True)
            subprocess.run([str(root/'test')],check=True)

if __name__=='__main__':unittest.main()
