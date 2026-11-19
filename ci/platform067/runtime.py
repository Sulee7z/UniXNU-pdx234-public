"""Interpret bounded handset log evidence without turning requests into observations."""
import re


def values(line):
    return dict(re.findall(r'([a-z][a-z0-9-]*)=([^\s,]+)', line))


def refresh_sample(line):
    data=values(line)
    if '[sony-present-rate]' in line:
        elapsed=int(data['elapsed-us'])
        if elapsed<=0:raise ValueError('Positive measured time interval required')
        return dict(kind='presentation',elapsed_us=elapsed,requested_vsync_hz=int(data['requested-vsync']),
            copies_per_second=int(data['copy-delta'])*1e6/elapsed,
            retirements_per_second=int(data['retire-delta'])*1e6/elapsed,
            compositor_fps=None,panel_refresh_hz=None,panel_refresh_verified=False)
    if '[sony-dpu-rate]' in line:
        elapsed=int(data['elapsed-us']);delta=int(data['delta'])
        enable=int(data['timing'],16);counter=int(data['counter-enable'],16)
        hz=delta*1e6/elapsed if elapsed>0 else 0
        valid=elapsed>=1000000 and 0<delta<0x80000000 and 0<hz<=240 and bool(enable&1) and bool(counter&1)
        return dict(kind='interface',interface=int(data['interface']),counter_valid=valid,
            observed_interface_hz=hz if valid else None,elapsed_us=elapsed,
            panel_refresh_hz=None,panel_refresh_verified=False)
    raise ValueError('Not a qualified Sony rate line')


def summarize(text):
    lines=text.splitlines()
    rates=[];invalid_rates=[]
    for line in lines:
        if '[sony-present-rate]' not in line and '[sony-dpu-rate]' not in line:continue
        try:rates.append(refresh_sample(line))
        except (ValueError,KeyError) as error:invalid_rates.append(dict(line=line,error=str(error)))
    counts={
        'apfs_enospc_lines':sum(('disk2s1' in line and ('; 28' in line or 'err 28' in line or 'ENOSPC' in line)) for line in lines),
        'explicit_no_space_lines':sum(('ENOSPC' in line or 'No space left on device' in line) for line in lines),
        'nonfatal_process_limit_lines':sum(('exceeded mem limit' in line and '(non-fatal)' in line) for line in lines),
        'fatal_process_limit_lines':sum(('exceeded mem limit' in line and '(fatal)' in line) for line in lines),
        'long_idle_exit_lines':sum('long-idle-exit' in line for line in lines),
        'highwater_kill_lines':sum(('memorystatus' in line and 'highwater' in line.lower()) for line in lines),
        'mach_port_guard_lines':sum(('EXC_GUARD' in line and 'type=0x1' in line) for line in lines),
    }
    touch=[]
    for match in re.finditer(r'\[sony-touch\] s=(\d+) e=(-?\d+) fw=([0-9a-fA-F]+) loaded=(\d+) clk=(\d+) frames=(\d+) valid=(\d+) bad=(\d+) contacts=(\d+) hid=(\d+) result=(-?\d+)',text):
        groups=match.groups();names=('stage','error','firmware','loaded','clock_level','frames','valid','bad','contacts','hid_reports','hid_result')
        touch.append({name:value if name=='firmware' else int(value) for name,value in zip(names,groups)})
    errors=[line for line in lines if any(marker in line for marker in
        ('[sony-touch] stage=', '[sony-buttons] refused', '[sony-buttons] hardware qualification failed',
         'SonyDsiUnqualified', '[sony-oled]', '[sony-wcn]'))]
    exits=[]
    pattern=(r'unixnu-exit: (.*?)\[(\d+)\] status=0x([0-9a-fA-F]+) '
             r'reason=(\d+)/0x([0-9a-fA-F]+) csflags=0x([0-9a-fA-F]+) description=([^\r\n]*)')
    for match in re.finditer(pattern,text):
        name,pid,status,namespace,code,csflags,description=match.groups()
        exits.append(dict(name=name,pid=int(pid),wait_status=int(status,16),
            reason_namespace=int(namespace),reason_code=int(code,16),csflags=int(csflags,16),
            description=description,classification='Recorded raw exit reason; not automatically a crash/PAC fault'))
    return dict(line_counts=counts,rate_samples=rates,malformed_rate_lines=invalid_rates,
        touch_last_sample=touch[-1] if touch else None,peripheral_messages=errors[-100:],
        official_process_exit_records=exits,
        all_app_exit_causes_proven=False,pac_cause_for_all_app_exits_proven=False,
        ios_heat_cause_proven=False,panel_refresh_verified=False,compositor_fps=None,
        interpretation='Line counts from rolling/captured text, not unique crashes or full-boot totals. '
            'Idle exits are not crashes; soft limits are not kills; DPU cadence is not panel TE/self-refresh.')
