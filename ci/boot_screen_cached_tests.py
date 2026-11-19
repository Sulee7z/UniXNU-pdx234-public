#!/usr/bin/env python3
"""Execute production cached painters/formatters and handoff/resume on a host framebuffer."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import shutil

import boot_screen_cached_overlay as overlay


def method(text, name):
    start = text.index(name)
    brace = text.index('{', start)
    depth, end = 1, brace+1
    while depth:
        depth += (text[end] == '{') - (text[end] == '}')
        end += 1
    return text[start:end]


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--base', type=Path, default=Path('/mnt/e/UniXNU-sheng27-sony-20261113'))
    p.add_argument('--out', type=Path, required=True)
    p.add_argument('--built', type=Path, help='Verify the freshly compiled archive and header dependencies')
    args = p.parse_args()
    if shutil.disk_usage('/mnt/g').free < 8*1024**3:
        raise RuntimeError('G: free space below 8 GiB')
    args.out.mkdir(parents=True, exist_ok=False)
    package = args.base/'sources/sheng/package'
    original = (package/'BootProgress.c').read_text()
    adapted = overlay.apply_usb(overlay.apply_progress(original))
    details = overlay.apply_trace_details((package/'BootUiTraceDetails.h').read_text())
    (args.out/'BootUiTraceDetails.h').write_text(details)
    for function, source in ((overlay.apply_progress, original), (overlay.apply_trace_details, (package/'BootUiTraceDetails.h').read_text())):
        for bad in (source+'\n', function(source)):
            try:
                function(bad)
            except ValueError:
                pass
            else:
                raise AssertionError('Accepted changed/already adapted source')
    probe = (args.base/'display-source-009/kits/sheng/LegacyDisplayProbe.cpp').read_text()
    overlay.qualify(probe, overlay.DISPLAY_PROBE_SHA256)
    types = probe[probe.index('enum {kSeenClients='):probe.index('typedef IOReturn (*ExternalFn)')]
    power = method(probe, 'extern "C" unsigned native_legacy_state_words')
    clients = method(probe, 'extern "C" unsigned native_legacy_clients_dump')
    header = Path(__file__).with_name('PdxBootCachedDiagnostics.h')
    font = Path(__file__).resolve().parents[2]/'uefi-pdx234/Silicon/Silicium/SiliciumPkg/Library/FrameBufferSerialPortLib'
    # Only replace ARM's store barrier in the host lifecycle extraction.
    lifecycle = '\n'.join(method(adapted, name) for name in (
        'static void refresh(unsigned now)', 'int boot_progress_prepare_scanout(void)',
        'void boot_progress_cancel_scanout(void)', 'static void touch_overlay(void)'))
    lifecycle = lifecycle.replace('__asm__ volatile("dsb sy" ::: "memory");', '__atomic_thread_fence(__ATOMIC_SEQ_CST);')
    code = r'''
#include <cassert>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <vector>
#define BP_COLS 120
#define uint64_t unsigned long long
#include "BootProgressCore.h"
#include "BootProgressDisplay.h"
#include "BootUiTraceCore.h"
#include "BootUiTraceDetails.h"
static bp_display display;
static unsigned now_value=1,state_calls,client_calls,data_calls;
static unsigned seconds(){return now_value;}
static char boot_progress_ext[8][48],boot_progress_ext_wide[2][112];
static void ext_data_rows(){++data_calls;}
static uintptr_t native_legacy_object;
static unsigned native_legacy_client_calls=4,native_legacy_client_successes=3;
''' + types + power.replace('native_legacy_state_words(', 'state_impl(') + clients.replace('native_legacy_clients_dump(', 'clients_impl(') + r'''
unsigned native_legacy_state_words(char *out,unsigned cap){++state_calls;return state_impl(out,cap);}
unsigned native_legacy_clients_dump(char *out,unsigned cap){++client_calls;return clients_impl(out,cap);}
#include "PdxBootCachedDiagnostics.h"
static unsigned enabled=1,render_busy,resume_after=10,boot_progress_display_owned,last_scanout_at;
static int state,render_snapshot;
static unsigned draws,banners;
static bool lock_ok=true,pulse_ok=true;
static int take(){return lock_ok;}static void release(){}
static void draw(unsigned){++draws;}
static struct {int closed;} pulse;
static int bp_pulse_enter(void*){return pulse_ok;}static void bp_pulse_close(void*){pulse.closed=1;}
static void bp_pulse_leave(void*){}
static unsigned line_calls,snapshot_calls,usb_value,usb_present=1,snapshot_ok=1,banner_value;
static void line(unsigned row,const char *,uint32_t){if(row>=17 && row<=19)++line_calls;}
static int PE_parse_boot_argn(const char *name,void *out,unsigned){
  if(!strcmp(name,"banner")){*(unsigned*)out=banner_value;return 1;}
  assert(!strcmp(name,"qcom-usb-debug"));*(int*)out=(int)usb_value;return usb_present;
}
int pdx_usb_screen_snapshot(char rows[3][192]){
  ++snapshot_calls;for(unsigned r=0;r<3;++r)strcpy(rows[r],"USB cached sentinel");return snapshot_ok;
}
static void crash_banner(unsigned){++banners;}
static unsigned touch_passes;
static unsigned native_touch_stage_req;
static void touch_overlay_locked(){}
''' + overlay.USB_ROWS + lifecycle + r'''
static void joined(unsigned start,unsigned count,char *out){
  out[0]=0;for(unsigned i=0;i<count;++i)strcat(out,pdx_cached_drawn[start+i]);
}
static void verify_pixels(const std::vector<uint32_t>& pixels,unsigned w,unsigned h,unsigned stride,unsigned scale,bool fits){
  unsigned x0=BP_COLS*6*scale+8,cols=w>x0+8?(w-x0-8)/(6*scale):0;if(cols>47)cols=47;
  unsigned rows=cols?8+2*((111+cols-1)/cols)+2*((127+cols-1)/cols):0;
  for(unsigned y=0;y<h;++y)for(unsigned x=0;x<stride/4;++x){
    uint32_t expected=0x12345678;
    if(fits && y>=13*14*scale && y<(13+rows)*14*scale && x>=x0 && x<x0+cols*6*scale){
      unsigned row=y/(14*scale)-13,col=(x-x0)/(6*scale),dy=(y/scale)%14,dx=((x-x0)/scale)%6;
      const char *s=pdx_cached_drawn[row];unsigned c=col<strlen(s)?(unsigned char)s[col]:' ';if(c<32||c>126)c='?';
      uint64_t glyph=font[c-32];unsigned bits=dy<6?(unsigned)(glyph>>(32+dy*5)):dy<12?(unsigned)(glyph>>((dy-6)*5)):0;
      unsigned wide_end=8+2*((111+cols-1)/cols);
      uint32_t color=row<4?0xff80ffff:row<wide_end?0xffffa0ff:0xffffff00;
      expected=dx<5&&((bits>>dx)&1)?color:0;
    }
    if(pixels[16+(size_t)y*(stride/4)+x]!=expected){fprintf(stderr,"pixel %ux%u scale%u at %u,%u got%x want%x fits%d\n",w,h,scale,x,y,pixels[16+(size_t)y*(stride/4)+x],expected,fits);abort();}
  }
  for(unsigned i=0;i<16;++i){assert(pixels[i]==0x12345678);assert(pixels[pixels.size()-1-i]==0x12345678);}
}
int main(int argc,char **argv){
  assert(argc==2);
  bt_main roles[4]={};char trace[BT_ROWS][120];roles[0].pid=90;roles[1].pid=30;
  roles[0].entry.trap=(uint64_t)-47;roles[0].entry.peer_code=2;
  roles[1].entry.trap=544;roles[1].entry.regs[1]=0x128019038ULL;roles[1].slide=0x1114000;
  roles[1].entry.peer=-1;roles[1].entry.peer_code=1;
  bt_main_rows(roles,0,trace);
  assert(strstr(trace[8],"trap=220 x1=128019038") && !strstr(trace[8],"opt="));
  assert(strstr(trace[7],"cache+=1114000"));
  assert(strstr(trace[6],"e1=not Mach2 e2=no remote") && strstr(trace[13],"e1=not Mach2 e2=no remote"));
  usb_value=(unsigned)atoi(argv[1]);usb_present=usb_value!=9;
  pdx_usb_boot_rows();assert(line_calls==(usb_value==1?3u:0u));assert(snapshot_calls==(usb_value==1?1u:0u));
  snapshot_ok=0;line_calls=0;pdx_usb_boot_rows();assert(!line_calls);
  // Exact display009 methods: distinguish requested/powered and attempts/successes;
  // poison selector count so entering the dump loop would fail under ASan.
  alignas(16) unsigned char object[7188];memset(object,0xa5,sizeof object);
  uint32_t requested=2,powered=1;memcpy(object+7180,&requested,4);memcpy(object+7184,&powered,4);
  native_legacy_object=(uintptr_t)object;seenClientCount=0xffffffff;
  char temp[512];assert(state_impl(nullptr,0)==0);assert(clients_impl(nullptr,0)==0);
  for(unsigned cap=1;cap<=128;++cap){char small[128];memset(small,0xcc,sizeof small);assert(clients_impl(small,cap)<cap);assert(memchr(small,0,cap));}
  assert(state_impl(temp,sizeof temp));assert(strstr(temp,"requested=2 powered=1"));
  for(unsigned i=0;i<8;++i)snprintf(boot_progress_ext[i],48,"slot%u cached status",i);
  for(unsigned i=0;i<111;++i){boot_progress_ext_wide[0][i]='A'+i%26;boot_progress_ext_wide[1][i]='a'+i%26;}
  memcpy(boot_progress_ext_wide[1],"PUB no Metal device ",20);
  memcpy(boot_progress_ext_wide[1]+91,"failure-tail-68f2XYZ",20);
  // Deliberately no producer terminator: only the 111-byte payload is consumed.
  boot_progress_ext_wide[0][111]=boot_progress_ext_wide[1][111]='!';
  struct Geometry{unsigned w,h,scale;bool fits;} cases[]={{1096,2560,1,true},{1644,3840,1,true},{1080,2520,1,true},
    {900,560,1,false},{900,574,1,true},{720,560,1,false},{736,560,1,false},{1096,461,1,false},{1096,462,1,true},{3000,1400,3,true},{2160,1400,3,false}};
  for(auto g:cases){
    unsigned stride=g.w*4+64;std::vector<uint32_t> pixels((size_t)stride/4*g.h+32,0x12345678);
    display={};display.frame=(uintptr_t)(pixels.data()+16);display.width=g.w;display.height=g.h;display.stride=stride;display.scale=g.scale;display.bound=1;
    pdx_cached_invalidate();ext_overlay_locked();verify_pixels(pixels,g.w,g.h,stride,g.scale,g.fits);
    if(!g.fits)continue;
    unsigned cols=(g.w-(BP_COLS*6*g.scale+8)-8)/(6*g.scale);if(cols>47)cols=47;
    unsigned parts=(111+cols-1)/cols;
    joined(8,parts,temp);assert(strlen(temp)==111 && !memcmp(temp,boot_progress_ext_wide[0],111));
    joined(8+parts,parts,temp);assert(strlen(temp)==111 && !memcmp(temp,boot_progress_ext_wide[1],111));
    assert(strstr(temp,"failure-tail-68f2XYZ"));
    unsigned base=8+parts*2,stateparts=(127+cols-1)/cols;
    joined(base,stateparts,temp);assert(strstr(temp,"requested=2 powered=1"));
    joined(base+stateparts,stateparts,temp);assert(strstr(temp,"attempts=4 successes=3"));
    auto before=pixels;unsigned count=state_calls;ext_overlay_locked();assert(pixels==before && state_calls==count);
    display.yield_requested=1;ext_overlay_locked();assert(pixels==before);display.yield_requested=0;
    display.bound=0;ext_overlay_locked();assert(pixels==before);display.bound=1;
  }
  // Actual handoff and resume functions, with only kernel locking/pulse services modeled.
  unsigned w=1096,h=2560,stride=w*4+64;std::vector<uint32_t> pixels((size_t)stride/4*h+32,0x12345678);
  display={};display.frame=(uintptr_t)(pixels.data()+16);display.width=w;display.height=h;display.stride=stride;display.scale=1;display.bound=1;
  pdx_cached_invalidate();ext_overlay_locked();auto before=pixels;
  render_busy=1;assert(!boot_progress_prepare_scanout());assert(display.bound && display.yield_requested);assert(pixels==before);
  boot_progress_cancel_scanout();assert(!display.yield_requested);render_busy=0;
  assert(boot_progress_prepare_scanout());assert(!display.bound && boot_progress_display_owned && pulse.closed);
  ext_overlay_locked();assert(pixels==before);
  refresh(now_value+9);assert(!display.bound && pixels==before);
  refresh(now_value+10);assert(display.bound);for(unsigned i=0;i<PDX_CACHED_ROWS;++i)assert(!pdx_cached_valid[i]);
  // banner=0 must still paint the bound boot page, but paint nothing on the UI.
  touch_overlay();assert(pdx_cached_valid[8] && !banners);
  assert(boot_progress_prepare_scanout());before=pixels;touch_overlay();assert(pixels==before && !banners);
  display.bound=1;now_value++;native_legacy_object=0;boot_progress_ext_wide[1][0]=0;
  ext_overlay_locked();joined(11,3,temp);assert(!temp[0]);joined(14,3,temp);assert(strstr(temp,"unavailable"));
  for(unsigned row=24;row<27;++row)for(unsigned y=row*14;y<(row+1)*14;++y)for(unsigned x=728;x<1010;++x)assert(pixels[16+(size_t)y*(stride/4)+x]==0);
  assert(state_calls==2 && client_calls==2);
  puts("PASS: exact pixels/bounds, full wide tails, cached D27 fields, USB gating, handoff/resume, banner=0, stale erase");
}
'''
    source = args.out/'actual-screen.cpp'
    source.write_text(code)
    command = ['clang++', '-std=c++17', '-O1', '-g', '-Wall', '-Wextra', '-Werror',
               '-Wno-ignored-attributes', '-Wno-pointer-bool-conversion', '-Wno-unused-function',
               '-fsanitize=address,undefined', '-fno-omit-frame-pointer', '-I'+str(args.out), '-I'+str(package),
               '-I'+str(font), '-I'+str(header.parent), str(source), '-o', str(args.out/'actual-screen')]
    subprocess.run(command, check=True)
    outputs = []
    for option in (0, 1, 2, 9):
        run = subprocess.run([str(args.out/'actual-screen'), str(option)], capture_output=True, text=True)
        (args.out/f'usb-{option}.log').write_text(run.stdout+run.stderr)
        if run.returncode:
            raise RuntimeError(run.stdout+run.stderr)
        outputs.append(dict(usb_option=option, output=run.stdout))
    assert 'opt=%llx' not in details and 'x1=%llx' in details
    assert 'e1=not Mach2 e2=no remote' in details
    receipt = dict(command=command, cases=outputs, source_sha256=hashlib.sha256(code.encode()).hexdigest(),
                   helper_sha256=hashlib.sha256(header.read_bytes()).hexdigest(),
                   display_probe_sha256=overlay.DISPLAY_PROBE_SHA256,
                   original_progress_sha256=overlay.PROGRESS_SHA256,
                   device_operations=False, runtime_verified=False)
    if args.built:
        result = json.loads((args.built/'result.json').read_text())
        archive = args.built/'libPdxBootScreen.a'
        assert hashlib.sha256(archive.read_bytes()).hexdigest() == result['sha256']
        assert (args.built/header.name).read_bytes() == header.read_bytes()
        assert (args.built/'BootUiTraceDetails.h').read_text() == details
        objects = []
        for name in ('BootProgress', 'BootUiTraceProbe', 'BootFaultProbe', 'BootProcessProbe'):
            cmd = json.loads((args.built/(name+'.command.json')).read_text())
            assert '-fptrauth-function-pointer-type-discrimination' in cmd
            assert '--target=arm64e-apple-ios27.0.0' in cmd
            identity = subprocess.check_output(['file', str(args.built/(name+'.o'))], text=True)
            assert 'arm64e' in identity
            objects.append(identity.strip())
        assert str(args.built/'PdxBootCachedDiagnostics.h') in (args.built/'BootProgress.o.d').read_text()
        assert str(args.built/'BootUiTraceDetails.h') in (args.built/'BootUiTraceProbe.o.d').read_text()
        # Compiler direct calls resolve to the existing source archive; no vtable
        # interposition, authentication rewrite or new hardware import is added.
        old = set(subprocess.check_output(['llvm-nm', '-u', str(args.base/'boot-screen-006/BootProgress.o')], text=True).splitlines())
        new = set(subprocess.check_output(['llvm-nm', '-u', str(args.built/'BootProgress.o')], text=True).splitlines())
        assert new-old == {'_native_legacy_state_words', '_native_legacy_clients_dump'}
        display_archive = args.base/'display-source-009/build/native-legacy-display/libNativeLegacyDisplay.late.a'
        symbols = subprocess.check_output(['llvm-nm', '--defined-only', str(display_archive)], text=True)
        assert ' T _native_legacy_state_words' in symbols and ' T _native_legacy_clients_dump' in symbols
        receipt['build'] = dict(archive=str(archive), sha256=result['sha256'], objects=objects,
                               new_imports=sorted(new-old), headers_verified=True,
                               retained006_sha256=hashlib.sha256((args.base/'boot-screen-006/libPdxBootScreen.a').read_bytes()).hexdigest())
    (args.out/'result.json').write_text(json.dumps(receipt, indent=2)+'\n')
    print(json.dumps(receipt, indent=2))


if __name__ == '__main__':
    main()
