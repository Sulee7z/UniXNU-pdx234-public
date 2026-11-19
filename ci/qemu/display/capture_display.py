"""Bounded read-only QEMU D27 display observations for a stopped current guest.

Import capture_display(packet, registers, symbols) from the runtime coordinator.
symbols must come from the exact selected final kernel. packet performs debugger
reads; the shared TTBR1 helper restores the original physical-read mode. No
guest function, PM request, memory write or framebuffer drawing is performed.
"""
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from d27_user_memory import read_kernel_memory

RECORD = struct.Struct('<10Q6I')
COUNTERS = {
    'native_legacy_object':8, 'native_legacy_stage':4,
    'native_legacy_surface_status':4, 'native_legacy_surface_found':4,
    'native_legacy_pm_stage':4, 'native_legacy_pm_status':4, 'native_legacy_pm_calls':4,
    'native_legacy_pm_callbacks':4, 'native_legacy_pm_ordinal':4,
    'native_legacy_client_calls':4, 'native_legacy_client_successes':4,
    'native_legacy_client_status':4, 'native_legacy_swap_validation_calls':4,
    'native_legacy_swap_validation_result':4, 'native_legacy_swap_validation_reason':4,
    'native_legacy_transfer_calls':4, 'native_legacy_transfer_status':4,
    'native_legacy_transfer_bytes':8, 'native_legacy_retirement_calls':4,
    'native_legacy_copy_n':8, 'native_legacy_copy_bytes_sum':8,
    'native_keyevents_stage':4, 'native_keyevents_status':4, 'native_keyevents_service':8,
    'native_aks_opens':4, 'native_aks_calls':4,
}
FIELDS = ('sequence','display','surface','descriptor','descriptorBytes','width','height','stride','current','pending',
          'event','requested','powered','format','planes','surfaceValid')


def capture_display(packet, registers, symbols):
    result=dict(source='Stopped D27 guest display observations through actual TTBR1',read_only=True,
                counters={},observations=[],reads=[],unavailable=[])

    def symbol(name):
        value=symbols.get('_'+name)
        return int(value,0) if isinstance(value,str) else value

    def read(address,size):
        captured=read_kernel_memory(packet,registers,address,size)
        result['reads'].append(captured)
        data=bytes.fromhex(captured['bytes'])
        if len(data)!=size:raise ValueError('Incomplete stopped-guest display read')
        return data

    for name,size in COUNTERS.items():
        address=symbol(name)
        if not address:
            result['unavailable'].append(name);continue
        value=int.from_bytes(read(address,size),'little')
        result['counters'][name]=value
    count=symbol('native_qemu_display_observation_count')
    ring=symbol('native_qemu_display_observations')
    if count and ring:
        total=int.from_bytes(read(count,4),'little')
        result['observation_count']=total
        for index in range(min(total,32)):
            row=dict(zip(FIELDS,RECORD.unpack(read(ring+index*RECORD.size,RECORD.size))))
            if row['sequence']!=index+1:
                result['unavailable'].append('incomplete observation '+str(index));continue
            result['observations'].append(row)
    else:
        result['unavailable'].append('QEMU display observation ring not linked')
    # Exact primitive RAM-recorder layout from PdxFramebufferCallDiagnostics.h.
    # Tokens and completion flags distinguish a real failed/returned selector
    # from an absent record. Inline scalar outputs are preserved verbatim.
    call_format=struct.Struct('<11Q9I4x')
    call_fields=('token','us','client','provider','input0','input1','input2','output0','output1',
                 'inputBytes','outputBytes','pid','selector','inputCount','outputCount','requested','powered',
                 'status','ended','stateValid')
    for name in ('pdx_mfb_first_failure','pdx_mfb_first_submit'):
        address=symbol(name)
        if address:
            result[name]=dict(zip(call_fields,call_format.unpack(read(address,call_format.size))))
    selectors=symbol('pdx_mfb_selectors')
    if selectors:
        data=read(selectors,101*12)
        result['framebuffer_selectors']=[dict(selector=index,calls=calls,failures=fails,status=status)
            for index,(calls,fails,status) in enumerate(struct.iter_unpack('<3I',data)) if calls]
    for name in ('pdx_mfb_issued','pdx_mfb_ended','pdx_mfb_failed','pdx_mfb_dropped'):
        address=symbol(name)
        if address:result['counters'][name]=int.from_bytes(read(address,4 if name.endswith('dropped') else 8),'little')
    result['limits']='One stopped snapshot; default-surface validity does not prove user-client export, composition or presentation'
    return result
