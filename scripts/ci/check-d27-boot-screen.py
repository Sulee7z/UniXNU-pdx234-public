#!/usr/bin/env python3
"""Run sheng recorder checks with explicit Linux host harness adaptations."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess

BASE=Path('/mnt/e/UniXNU-sheng27-sony-20261113')


def main():
    upstream=BASE/'sources/sheng';out=BASE/'boot-screen-checks-002'
    (out/'scripts').mkdir(parents=True,exist_ok=False)
    (out/'kits/sheng').mkdir(parents=True)
    for p in (upstream/'package').glob('Boot*'):
        if p.is_file():shutil.copyfile(p,out/'kits/sheng'/p.name)
    for p in (BASE/'boot-screen-002').glob('*.c'):shutil.copyfile(p,out/'kits/sheng'/p.name)
    (out/'uefi-sheng').symlink_to('/mnt/g/UniXNU-Port/ports/uefi-pdx234',target_is_directory=True)
    # Darwin uint64_t is unsigned long long; Linux uses unsigned long. Both
    # are 64-bit here, so use the Darwin typedef within the host-only harness.
    tools=out/'host-bin';tools.mkdir()
    (tools/'clang').write_text(r'''#!/usr/bin/env python3
import os,sys
from pathlib import Path
args=sys.argv[1:]
for arg in args:
 if arg.endswith('/test.c'):
  p=Path(arg);text=p.read_text()
  text=text.replace('#include <stdint.h>', '#include <stdint.h>\n#define uint64_t unsigned long long')
  p.write_text(text)
os.execv('/usr/bin/clang',['clang',*args])
''')
    (tools/'clang').chmod(0o755)
    results=[]
    for name in ['check-boot-progress-host.py','check-boot-lifecycle.py','check-boot-diag-resume.py',
                 'check-boot-fault-probe.py','check-boot-process-probe.py','check-boot-pulse.py']:
        text=(upstream/'scripts'/name).read_text();original=text
        if name=='check-boot-diag-resume.py':
            text=text.replace('char previous[48][BP_COLS];','char previous[48][BP_COLS];uint32_t colors[48][2];')
        if name=='check-boot-pulse.py':
            text=text.replace("assert platform.system()=='Darwin' and platform.machine()=='arm64'",
                              '# Linux host model: ARM barrier substituted by host fence below.')
            text=text.replace('c.write_text(prefix+handoff+worker+main)',
                'c.write_text((prefix+handoff+worker+main).replace(\'__asm__ volatile("dsb sy" ::: "memory");\',\'__atomic_thread_fence(__ATOMIC_SEQ_CST);\'))')
        if name=='check-boot-lifecycle.py':
            # The upstream slice grew to include independent spawn/profile
            # functions. Test the two lifecycle functions this harness calls.
            text=text.replace("s.index('void boot_progress_irq(')", 's.index("// The log\'s [spawn]")')
            text=text.replace('static int recorder_busy;', '''static int recorder_busy;
static void census_note(const char *name,unsigned exit){(void)name;(void)exit;}
static int proc_selfpid(void){return -1;}
static void xpc_fail_note(int status,unsigned ns,uint64_t code){(void)status;(void)ns;(void)code;}
static void (*boot_progress_exit_reason)(int,unsigned,char *,unsigned long);
static char boot_progress_throw_text[330];
static size_t strlcpy(char *d,const char *s,size_t n){size_t len=strlen(s);if(n){size_t k=len<n-1?len:n-1;memcpy(d,s,k);d[k]=0;}return len;}
''')
            text=text.replace("'-Wno-unused-function',", "'-Wno-unused-function','-Wno-pointer-bool-conversion',")
        script=out/'scripts'/name;script.write_text(text)
        env=dict(os.environ,PATH=str(tools)+':'+os.environ['PATH'])
        q=subprocess.run(['python3','-B',str(script)],env=env,capture_output=True,text=True)
        (out/(name+'.log')).write_text(q.stdout+q.stderr)
        results.append(dict(check=name,returncode=q.returncode,original_sha256=hashlib.sha256(original.encode()).hexdigest(),
                            harness_sha256=hashlib.sha256(text.encode()).hexdigest()))
        print(name,q.returncode,(q.stdout+q.stderr)[-2500:])
    (out/'result.json').write_text(json.dumps(results,indent=2)+'\n')
    if any(r['returncode'] for r in results):raise SystemExit(1)


if __name__=='__main__':main()
