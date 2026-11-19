// SPDX-License-Identifier: BSD-2-Clause-Patent
// Real Linux PID1 fixture. This is not Android userspace or SpringBoard.
typedef unsigned long word;
static long call(word n, word a, word b, word c) {
  register word x8 __asm__("x8")=n;
  register word x0 __asm__("x0")=a;
  register word x1 __asm__("x1")=b;
  register word x2 __asm__("x2")=c;
  __asm__ volatile("svc #0" : "+r"(x0) : "r"(x8),"r"(x1),"r"(x2) : "memory");
  return (long)x0;
}
static word length(const char *s) { word n=0; while(s[n])++n;return n; }
static void put(const char *s) {
  word n=length(s);while(n){long w=call(64,1,(word)s,n);if(w<=0)break;s+=w;n-=w;}
}
static int same(const char *a,const char *b) { while(*a && *a==*b){++a;++b;}return *a==*b; }
__attribute__((noreturn)) void _start(void) {
  char uts[6][65];
  long pid=call(172,0,0,0);
  long status=call(160,(word)uts,0,0);
  if(pid==1 && status==0 && same(uts[0],"Linux") && same(uts[4],"aarch64")) {
    put("QEMU-ANDROID-LINUX: PASS pid=1 machine=aarch64 release=");put(uts[2]);put("\n");
  } else {
    put("QEMU-ANDROID-LINUX: FAIL PID1/uname\n");
  }
  word delay[2]={3600,0};
  for(;;)call(101,(word)delay,0,0);
}
