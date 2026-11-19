#!/usr/bin/env python3
"""Run the actual old/fixed writer bodies with modeled vnode contracts, ASan+UBSan.

The model intentionally represents XNU's non-compound vnode_open not finishing
O_TRUNC. It is not APFS or hardware validation. Only the assigned directory is written.
"""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess

from audit import HERE, BASE, sha


PREAMBLE = r'''
#include <assert.h>
#include <errno.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
typedef void *vfs_context_t;
typedef char *caddr_t;
typedef long off_t;
typedef struct model *vnode_t;
#define NULLVP NULL
#define FREAD 1
#define FWRITE 2
#define O_NOFOLLOW 4
#define O_CREAT 8
#define O_TRUNC 16
#define UIO_WRITE 0
#define UIO_SYSSPACE 0
#define IO_NOAUTH 1
#define IO_UNIT 2
#define MNT_WAIT 1
struct model { size_t size; uint32_t mode; uint8_t bytes[128]; } node;
struct vnode_attr { unsigned active; uint32_t va_mode; uint64_t va_data_size; };
#define VATTR_INIT(va) memset((va),0,sizeof(*(va)))
#define ATTR_va_mode 1
#define ATTR_va_data_size 2
#define VATTR_SET(va,field,value) do { (va)->field=(value); (va)->active|=ATTR_##field; } while(0)
static int open_error, write_error, setattr_error, sync_error, close_error, residual, equal;
static unsigned opens, closes, sets, writes, syncs;
static int vnode_open(const char *p, int flags, int mode, int other, vnode_t *vp, vfs_context_t ctx) {
 (void)p;(void)mode;(void)other;(void)ctx;++opens;
 if(open_error && (flags & FWRITE))return open_error;
 *vp=&node;return 0;
}
static int vnode_close(vnode_t vp,int flags,vfs_context_t ctx) {
 (void)vp;(void)ctx;++closes;return flags==FWRITE?close_error:0;
}
static void *vfs_context_ucred(vfs_context_t c){return c;}
static void *vfs_context_proc(vfs_context_t c){return c;}
static int vn_rdwr(int op,vnode_t vp,caddr_t data,int size,off_t off,int seg,int flags,void *cred,int *resid,void *proc) {
 (void)op;(void)seg;(void)flags;(void)cred;(void)proc;++writes;
 *resid=residual;
 if(write_error)return write_error;
 assert(size>=0 && (size_t)size<=sizeof(vp->bytes));
 if(size)memcpy(vp->bytes+off,data,(size_t)size);
 if(vp->size<(size_t)size)vp->size=(size_t)size;
 return 0;
}
static int vnode_setattr(vnode_t vp,struct vnode_attr *va,vfs_context_t ctx) {
 (void)ctx;++sets;if(setattr_error)return setattr_error;
 if(va->active&ATTR_va_mode)vp->mode=va->va_mode;
 if(va->active&ATTR_va_data_size)vp->size=(size_t)va->va_data_size;
 return 0;
}
static int VNOP_FSYNC(vnode_t vp,int how,vfs_context_t ctx){(void)vp;(void)how;(void)ctx;++syncs;return sync_error;}
static int native_gpu_addon_equal(vnode_t vp,const uint8_t *data,uint64_t size,uint32_t mode,vfs_context_t ctx) {
 (void)vp;(void)data;(void)size;(void)mode;(void)ctx;return equal;
}
'''

TESTS = r'''
static void reset(size_t size) {
 memset(&node,0,sizeof(node));node.size=size;memset(node.bytes,0x41,sizeof(node.bytes));
 open_error=write_error=setattr_error=sync_error=close_error=residual=equal=0;
 opens=closes=sets=writes=syncs=0;
}
int main(void) {
 const uint8_t data[]={1,2,3};unsigned cases=0;
 reset(20);assert(old_writer("p",data,3,0644,NULL)==0 && node.size==20);++cases;
 reset(20);assert(fixed_writer("p",data,3,0644,NULL)==0 && node.size==3 && !memcmp(node.bytes,data,3) && opens==2);++cases;
 reset(0);assert(fixed_writer("p",data,3,0600,NULL)==0 && node.size==3 && node.mode==0600);++cases;
 reset(20);assert(fixed_writer("p",data,0,0600,NULL)==0 && node.size==0);++cases;
 reset(3);equal=1;assert(fixed_writer("p",data,3,0644,NULL)==-1 && writes==0 && sets==0);++cases;
 reset(20);open_error=EACCES;assert(fixed_writer("p",data,3,0644,NULL)==EACCES && writes==0);++cases;
 reset(20);write_error=ENOSPC;assert(fixed_writer("p",data,3,0644,NULL)==ENOSPC && sets==0 && syncs==0 && closes==2);++cases;
 reset(20);residual=1;assert(fixed_writer("p",data,3,0644,NULL)==EIO && sets==0 && syncs==0);++cases;
 reset(20);setattr_error=EIO;assert(fixed_writer("p",data,3,0644,NULL)==EIO && syncs==0 && node.size==20);++cases;
 reset(20);sync_error=EIO;assert(fixed_writer("p",data,3,0644,NULL)==EIO && node.size==3);++cases;
 reset(20);close_error=EBUSY;assert(fixed_writer("p",data,3,0644,NULL)==EBUSY);++cases;
 reset(20);write_error=ENOSPC;close_error=EBUSY;assert(fixed_writer("p",data,3,0644,NULL)==ENOSPC);++cases;
 printf("PASS %u actual-body modeled-vnode cases; old shorter-file tail reproduced\n",cases);return 0;
}
'''


def extract(text: str) -> str:
    start = text.index('static int\nnative_gpu_addon_write(')
    end = text.index('\n/* Creates the missing parent directories', start)
    return text[start:end]


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--out', type=Path, default=HERE / 'addon-writer-tests-003')
    p.add_argument('--compiler', default='clang-18')
    a = p.parse_args()
    out = a.out.resolve()
    if not out.is_relative_to(HERE) or out == HERE or out.exists():
        raise ValueError('Require new assigned output directory')
    baseline = BASE / 'native-screen007-055-001/native-source/kern_exec.c'
    fixed = HERE / 'addon-size-compile-001/kern_exec.c'
    out.mkdir()
    source = PREAMBLE + extract(baseline.read_text()).replace('native_gpu_addon_write(', 'old_writer(', 1)
    source += extract(fixed.read_text()).replace('native_gpu_addon_write(', 'fixed_writer(', 1) + TESTS
    target = out / 'test.c'
    target.write_text(source)
    binary = out / 'test'
    command = [a.compiler, '-std=c11', '-Wall', '-Wextra', '-Werror', '-O1', '-g',
               '-fsanitize=address,undefined', '-fno-omit-frame-pointer', str(target), '-o', str(binary)]
    done = subprocess.run(command, capture_output=True, text=True, timeout=90)
    (out / 'compile.log').write_text(done.stdout + done.stderr)
    if done.returncode:
        raise RuntimeError(done.stderr)
    run = subprocess.run([str(binary)], capture_output=True, text=True, timeout=30)
    (out / 'run.log').write_text(run.stdout + run.stderr)
    if run.returncode:
        raise RuntimeError(run.stderr)
    record = {'passed': True, 'cases': 12, 'source': str(target), 'source_sha256': sha(target),
              'baseline_source_sha256': sha(baseline), 'fixed_source_sha256': sha(fixed),
              'command': command, 'sanitizers': ['address', 'undefined'], 'old_shorter_tail_reproduced': True,
              'size_zero_grow_shrink_and_equal': True, 'error_propagation_retained': True,
              'limits': 'Actual extracted writer bodies; mocked vnode_open/vn_rdwr/setattr/fsync/close. No APFS or handset validation.'}
    (out / 'result.json').write_text(json.dumps(record, indent=2) + '\n')
    print(run.stdout.strip())


if __name__ == '__main__':
    main()
