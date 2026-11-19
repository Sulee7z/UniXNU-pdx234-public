"""Pinned D27 Swift fatal-message collector for the ordinary SIGTRAP exit path."""
import hashlib
from pathlib import Path

FAULT_SHA256 = '462055b592aa20d2330d7d99a8a374c22ad3b92b10aff0609f26e0246a425964'
HEADER = 'PdxSwiftTrapDiagnostic.h'

ADAPTER = r'''
#include <ptrauth.h>
#include "PdxSwiftTrapDiagnostic.h"
static int pdx_swift_fault_read(void *context,uint64_t address,void *out,size_t bytes) {
 (void)context;return copyin((user_addr_t)address,out,bytes);
}
static uint64_t pdx_swift_fault_strip_return(void *context,uint64_t value) {
 (void)context;return (uint64_t)ptrauth_strip((void *)(uintptr_t)value,ptrauth_key_return_address);
}
// Only called from ordinary exit, after releasing fault_lock. A mismatching
// PID/thread publishes unavailable status without invoking the user reader.
static void pdx_swift_fault_record(const struct boot_fault_record *fault,int pid,unsigned signal) {
 struct pdx_swift_snapshot snapshot={0};struct pdx_swift_result result;
 snapshot.valid=fault->valid;snapshot.signal=signal;snapshot.pid=fault->pid;
 snapshot.exit_pid=pid;snapshot.current_pid=proc_selfpid();
 snapshot.thread_id=fault->thread_id;snapshot.current_thread_id=current_thread()->thread_id;
 snapshot.ordinary_exit=!ml_at_interrupt_context();
 snapshot.pc=fault->pc;snapshot.sp=fault->sp;snapshot.fp=fault->fp;
 snapshot.esr=fault->esr;snapshot.slide=fault->slide;snapshot.x20=fault->x[20];snapshot.x21=fault->x[21];
 if(snapshot.ordinary_exit && snapshot.pid==snapshot.current_pid && snapshot.pid==pid &&
    snapshot.thread_id && snapshot.thread_id==snapshot.current_thread_id)
  snapshot.user_limit=vm_map_max(current_map());
 struct pdx_swift_reader reader={0,pdx_swift_fault_read,pdx_swift_fault_strip_return};
 if(pdx_swift_trap_collect(&snapshot,&reader,&result))pdx_swift_trap_publish(&result);
}
'''


def replace_once(text, old, new):
    if text.count(old) != 1:
        raise ValueError(f'Unreviewed Swift diagnostic anchor: {old[:80]}')
    return text.replace(old, new, 1)


def adapt_fault(text):
    """Accept only the qualified upstream source; never mutate its source file."""
    if hashlib.sha256(text.encode()).hexdigest() != FAULT_SHA256:
        raise ValueError('Unreviewed BootFaultProbe revision for Swift diagnostic')
    text = replace_once(text, ' uint64_t pc,lr,sp,fp,esr,far,slide,x[29];',
                        ' uint64_t thread_id,pc,lr,sp,fp,esr,far,slide,x[29];')
    text = replace_once(text, 'static unsigned fault_lock,fault_count;',
                        'static unsigned fault_lock,fault_count;\n'+ADAPTER)
    text = replace_once(text, ' f->valid=0;f->pid=proc_selfpid();proc_selfname(f->name,sizeof(f->name));',
                        ' f->valid=0;f->pid=proc_selfpid();f->thread_id=current_thread()->thread_id;proc_selfname(f->name,sizeof(f->name));')
    text = replace_once(text, '// No user memory access on the ordinary noncritical exit reporting path.',
                        '// Qualified Swift messages use bounded copyin on the ordinary exit path only.')
    start = text.index('void boot_progress_exit_fault(')
    end = text.index('// Called on the ordinary exit path before coredump/sync,', start)
    function = text[start:end]
    function = replace_once(function, ' struct boot_fault_record f={0};',
                            ' struct boot_fault_record f={0},swift_unmatched={0};\n const uint64_t exiting_thread_id=current_thread()->thread_id;')
    function = replace_once(function, '  if(candidate->valid && candidate->pid==pid){f=*candidate;break;}',
                            '''  if(candidate->valid && candidate->pid==pid) {
   if(candidate->thread_id==exiting_thread_id){f=*candidate;break;}
   if(!swift_unmatched.valid && candidate->esr==PDX_SWIFT_TRAP_ESR && candidate->pc>=candidate->slide &&
      candidate->pc-candidate->slide==PDX_SWIFT_TRAP_PC)swift_unmatched=*candidate;
  }''')
    function = replace_once(function, ' if(!f.valid)return;', ''' if(signal==5) {
  if(f.valid && f.pid==pid && f.thread_id==exiting_thread_id)
   pdx_swift_fault_record(&f,pid,signal);
  else if(swift_unmatched.valid)pdx_swift_fault_record(&swift_unmatched,pid,signal);
 }
 if(!f.valid)return;''')
    return text[:start]+function+text[end:]


def stage_header(out):
    """Copy the exact header into an existing fresh build staging directory."""
    source = Path(__file__).with_name(HEADER)
    destination = Path(out)/HEADER
    data = source.read_bytes()
    if destination.exists() and destination.read_bytes() != data:
        raise ValueError('Refusing to overwrite a different staged Swift diagnostic header')
    destination.write_bytes(data)
    return dict(path=str(destination), sha256=hashlib.sha256(data).hexdigest())
