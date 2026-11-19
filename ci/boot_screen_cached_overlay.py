"""Replay the boot-page cached diagnostics without changing the live banner."""
from pathlib import Path
import hashlib

PROGRESS_SHA256 = '6b49a811288703fb009f03e37eb26f601a64d6d62e08a3bda864a8ed3f64e213'
DETAILS_SHA256 = 'fd0cade54640c3188ba8f0e5a7e490a759576a3b0ba0fb90c47aabb6864e215d'
DISPLAY_PROBE_SHA256 = 'd5f9692a8f2d6cc154239f5129fe9c14c4a999d0db3ff15f2578dd908c0ed855'


def qualify(text, expected):
    if hashlib.sha256(text.encode()).hexdigest() != expected:
        raise ValueError('Unreviewed cached diagnostic source revision')


def replace_once(text, old, new):
    if text.count(old) != 1:
        raise ValueError(f'Unreviewed boot screen anchor: {old[:80]}')
    return text.replace(old, new)


def apply_progress(text):
    qualify(text, PROGRESS_SHA256)
    first = text.index('static char ext_drawn[8][48];')
    last = text.index('// Crash banner:', first)
    if text[first:last].count('static void ext_overlay_locked(void)') != 1:
        raise ValueError('Unreviewed extension renderer')
    text = text[:first] + '#include "PdxBootCachedDiagnostics.h"\n' + text[last:]
    text = replace_once(text, 'static struct bp_display display;',
                        'static void pdx_cached_invalidate(void);\nstatic struct bp_display display;')
    if text.count('bp_clear(&display);') != 2:
        raise ValueError('Unreviewed bind/resume lifecycle')
    text = text.replace('bp_clear(&display);', 'bp_clear(&display);pdx_cached_invalidate();')
    text = replace_once(text, '// Two wider GPU rows (GPU7, GPU8) for result lines that do not fit 47 columns; the live banner only.',
                        '// Two wider GPU rows (GPU7, GPU8), wrapped completely on the boot page and retained in the live banner.')
    text = replace_once(text, '  if(banner_off)return;', '  if(banner_off && !display.bound)return;')
    text = replace_once(text, '  crash_banner(seconds());', '  if(!banner_off)crash_banner(seconds());')
    return text


def apply_trace_details(text):
    qualify(text, DETAILS_SHA256)
    return replace_once(text, 'trap=%llx opt=%llx remote=', 'trap=%llx x1=%llx remote=')


TRACE_PROBE_SHA256 = '04f4d9f993a7b4264cd782527043bbbe76935bc4ebb4b14f1529d5ffb9801612'


def apply_first_frame_progress(text):
    text = replace_once(text, 'static unsigned seconds(void);',
                        'static unsigned seconds(void);\n#include "PdxProcessChurnDiagnostics.h"')
    text = replace_once(text, '#include "PdxBootCachedDiagnostics.h"',
                        '#include "PdxGpuProgressCache.h"\n#include "PdxFramebufferCallDiagnostics.h"\n#include "PdxFirstFrameDiagnostics.h"\n#include "PdxBootCachedDiagnostics.h"')
    text = replace_once(text, 'display.scale=w>=2160 && h>=1400?3:1;',
                        'display.scale=w>=2160 && h>=1400?3:1;\n    {unsigned diag=0;PE_parse_boot_argn("first-frame-diag",&diag,sizeof diag);if(diag==1)display.scale=1;}')
    text = replace_once(text, '    touch_overlay();\n    uint64_t f,t0,t1;',
                        '    touch_overlay();\n    pdx_gpu_progress_poll();\n    uint64_t f,t0,t1;')
    text = replace_once(text, '  if(!enabled || !take())return;\n  char stamped[BP_COLS];unsigned now=seconds();',
                        '  if(enabled)pdx_churn_exec(pid,name,text);\n  if(!enabled || !take())return;\n  char stamped[BP_COLS];unsigned now=seconds();')
    text = replace_once(text, '  census_note(name,1);', '  pdx_churn_exit(pid,name,status,ns,code);\n  census_note(name,1);')
    return replace_once(text, 'if(!strncmp(text,"exec process signature",22))census_note(name,0);',
                        'if(!strcmp(text,"exec process signature enter"))census_note(name,0);')


def apply_first_frame_trace(text):
    qualify(text, TRACE_PROBE_SHA256)
    text = replace_once(text, 'void boot_ui_trace_begin(void) {',
                        '#include "PdxRenderThreadDiagnostics.h"\nvoid boot_ui_trace_begin(void) {\n pdx_render_begin();')
    text = replace_once(text, '  bt_add(&draft,&samples[i]);\n }\n {',
                        '  bt_add(&draft,&samples[i]);\n }\n pdx_render_collect(role,pid,slide,count);\n {')
    return replace_once(text, '  published=draft;memcpy(published_main',
                        '  pdx_render_publish();\n  published=draft;memcpy(published_main')


USB_ROWS = '''extern int pdx_usb_screen_snapshot(char [3][192]) __attribute__((weak_import));
static void pdx_usb_boot_rows(void) {
  static int selected=-1;
  if(selected<0) {
    int opt=0;selected=PE_parse_boot_argn("qcom-usb-debug",&opt,sizeof(opt)) && opt==1;
  }
  if(!selected || !pdx_usb_screen_snapshot)return;
  char rows[3][192]={{0}};
  if(!pdx_usb_screen_snapshot(rows))return;
  for(unsigned r=0;r<3;++r) {
    rows[r][191]=0;
    if(rows[r][0])line(17+r,rows[r],0xffffaa00);
  }
}
'''


def apply_usb(text):
    text = replace_once(text, 'static void draw(unsigned now) {', USB_ROWS+'static void draw(unsigned now) {')
    anchor = '  snprintf(b,sizeof(b),"MEM totalMiB='
    return replace_once(text, anchor, '  pdx_usb_boot_rows();\n'+anchor)


def stage_headers(out):
    source = Path(__file__).with_name('PdxBootCachedDiagnostics.h')
    (out/source.name).write_bytes(source.read_bytes())
    details = out/'BootUiTraceDetails.h'
    details.write_text(apply_trace_details(details.read_text()))
