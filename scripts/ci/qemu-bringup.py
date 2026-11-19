#!/usr/bin/env python3
"""Emit an experimental allow-missing kernel and boot it in QEMU on the macOS runner.

Two offline subcommands:

  emit   re-run the pinned prelink emitter with --allow-missing (after the strict
         build step failed), copy the full kernel.json report into the public log
         directory, seal the candidate with the board kernel arguments and record
         the checkpoint addresses taken from the candidate's own symbol table.
  boot   stage an ESP from the sealed candidate, the built UniXNU/DarwinBoot
         loaders and a make-dt.py ADT, then run QEMU once for the serial console
         and once per gdb-stop checkpoint (_arm_init, _panic,
          _unixnu_fileset_unmapped, _IOFindBSDRoot).

Only text logs, JSON reports and PNG screenshots are written to --logs. The
candidate stays under --work and is never uploaded; strict emission remains the
delivery gate and this helper never replaces it.
"""
import argparse
from bisect import bisect_right
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tomllib
from types import SimpleNamespace

CHECKPOINTS = ['_arm_init', '_panic', '_unixnu_fileset_unmapped', '_IOFindBSDRoot']
STOP_GUARDS = ['_panic', '_Assert', '_unixnu_fileset_unmapped']
BOOT_TRACES = ['_source_corecrypto14_bootstrap', '_register_and_init_prng', '_bsd_init',
               '_IOKitBSDInit', '_bsdinit_task']
BOOT_OBSERVERS = {'_source_corecrypto14_status': 4, '_prng_ready': 4, '_rootvnode': 8, '_rootdev': 4}


def sha256(path):
    import hashlib
    digest = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for chunk in iter(lambda: stream.read(1 << 20), b''):
            digest.update(chunk)
    return digest.hexdigest()


def load_board(device):
    return tomllib.loads((device / 'board.toml').read_text())


def load_spec(device, board):
    name = board['board']['os_profile']
    profile = tomllib.loads((device / 'profiles' / name / 'profile.toml').read_text())
    return profile, profile['kernel']['prelink']


def merged_boot_arguments(base, overrides):
    """Apply QEMU-only overrides without changing the device's payload arguments."""
    values = {}
    for value in [*base, *overrides]:
        if not re.fullmatch(r'[A-Za-z0-9_.-]+(?:=[A-Za-z0-9_.,-]+)?', value):
            raise ValueError('Unsupported kernel argument: ' + value)
        values[value.split('=', 1)[0]] = value
    line = ' '.join(values.values())
    if len(line.encode('ascii')) > 1000:
        raise ValueError('QEMU kernel command line exceeds 1000 bytes')
    return line


def find_kernelcache(mainline):
    found = sorted((mainline / 'out/ipsw').glob('*/kernelcache.decompressed'))
    if len(found) != 1:
        raise SystemExit(f'expected one extracted kernelcache, found {len(found)}')
    return found[0]


def emit_command(spec, kernelcache, output, allow_missing=True):
    command = [sys.executable, '-B', spec['tool'],
               '--kernel', spec['kernel'], '--prelinked', str(kernelcache),
               f'--slide={int(spec["slide"], 0)}']
    for root in spec.get('roots', []):
        command += ['--root', root]
    if spec.get('early_security_init'):
        command += ['--early-security-init', spec['early_security_init']]
    command += spec.get('extra_args', [])
    if allow_missing:
        command.append('--allow-missing')
    command += ['--output', str(output)]
    return command


def unresolved(report):
    missing = report.get('missing') or {}
    stubbed = report.get('stubbed') or {}
    targets = 0
    unique = set()
    bundles = set()
    for table in (missing, stubbed):
        for owner, entries in table.items():
            bundles.add(owner)
            targets += sum(entries.values())
            unique.update(entries)
    return {'references': targets, 'unique_targets': len(unique),
            'bundles': len(bundles),
            'stubbed_references': sum(sum(v.values()) for v in stubbed.values())}


def checkpoint_addresses(candidate, kit):
    sys.path.insert(0, str(kit))
    from kc_image import Image
    data = Path(candidate).read_bytes()
    cache = Image(data)
    member = Image(data, cache.entries['com.apple.kernel'][1])
    names = {name: address for address, values in member.symbols().items() for name in values}
    return {name: hex(names[name]) if name in names else None
            for name in dict.fromkeys([*CHECKPOINTS, *STOP_GUARDS])}


def checkpoint_guard_options(address, checkpoints):
    """Catch the first actual panic/assert/unmapped call in this same guest."""
    options = []
    seen = {address}
    for name in STOP_GUARDS:
        target = checkpoints.get(name)
        if target and target not in seen:
            seen.add(target)
            options += ['--also-stop', target]
    return options


def boot_observer_addresses(candidate, kit):
    sys.path.insert(0, str(kit))
    from kc_image import Image
    data = Path(candidate).read_bytes()
    collection = Image(data)
    member = Image(data, collection.entries['com.apple.kernel'][1])
    names = {name: address for address, values in member.symbols().items() for name in values}
    return ({name: hex(names[name]) for name in BOOT_TRACES if name in names},
            {name: {'address': hex(names[name]), 'bytes': length}
              for name, length in BOOT_OBSERVERS.items() if name in names})


def decode_boot_observers(observers, memory):
    """Decode only complete reads at symbols from the exact candidate; absent is not zero."""
    result = {}
    for name, observer in observers.items():
        request = observer['address'] + ':' + hex(observer['bytes'])
        raw = memory.get(request)
        entry = dict(observer, raw=raw)
        if not isinstance(raw, str) or not re.fullmatch(r'[0-9a-fA-F]{%d}' %
                                                       (observer['bytes'] * 2), raw):
            entry['status'] = 'unreadable or absent'
        else:
            entry.update(status='read', value=int.from_bytes(bytes.fromhex(raw), 'little'))
        result[name] = entry
    return result


def decode_kernel_timeout_panic(stop):
    """Darwin arm64 printf variadic arguments are stack slots, not x1-x4."""
    fmt = (stop.get('argument_memory') or {}).get('x0')
    if fmt != '%s %s (start: %llu, end: %llu)%s':
        return None
    raw = stop.get('stack_bytes')
    if not isinstance(raw, str) or len(raw) < 80 or not re.fullmatch(r'[0-9a-fA-F]+', raw) or len(raw) % 2:
        return None
    stack = bytes.fromhex(raw)
    values = [int.from_bytes(stack[index * 8:index * 8 + 8], 'little') for index in range(5)]
    strings = {}
    for index in (0, 1, 4):
        capture = (stop.get('stack_pointer_memory') or {}).get(str(index)) or {}
        if capture.get('address') != hex(values[index]):
            return None
        data = capture.get('bytes')
        if not isinstance(data, str) or len(data) % 2 or not re.fullmatch(r'[0-9a-fA-F]+', data):
            return None
        text = bytes.fromhex(data)
        end = text.find(b'\0')
        if end < 0:
            return None
        try:
            strings[index] = text[:end].decode('utf-8')
        except UnicodeDecodeError:
            return None
    return {'reason': strings[0], 'duration': strings[1], 'start': values[2], 'end': values[3],
            'text': f'{strings[0]} {strings[1]} (start: {values[2]}, end: {values[3]}){strings[4]}',
            'argument_abi': 'Darwin arm64 variadic stack slots'}


def symbolize_function(image, raw_address, va_bits):
    """Resolve a captured pointer only inside this image's exact function ranges."""
    ranges = [s for s in image.segments if s['name'] in ('__TEXT_EXEC', '__TEXT_BOOT_EXEC', '__KLD')]
    mask = (1 << va_bits) - 1
    candidates = [raw_address, (raw_address & mask) | (image.base & ~mask)]
    segment = None
    for address in candidates:
        segment = next((s for s in ranges if s['va'] <= address < s['va'] + s['filesize']), None)
        if segment is not None:
            break
    if segment is None:
        return {'raw': hex(raw_address), 'status': 'outside native executable ranges'}
    starts = sorted(image.function_starts())
    index = bisect_right(starts, address) - 1
    if index < 0 or starts[index] < segment['va']:
        return {'raw': hex(raw_address), 'address': hex(address), 'status': 'function start absent'}
    start = starts[index]
    end = min(starts[index + 1] if index + 1 < len(starts) else segment['va'] + segment['filesize'],
              segment['va'] + segment['filesize'])
    function_bytes = image.read(start, end - start)
    return {'raw': hex(raw_address), 'address': hex(address), 'status': 'resolved',
            'function_start': hex(start), 'function_end': hex(end), 'offset': address - start,
            'names': image.symbols().get(start, []),
            'function_sha256': hashlib.sha256(function_bytes).hexdigest(),
            'complete_function_bytes': function_bytes.hex() if len(function_bytes) <= 4096 else None,
            'instruction_bytes': image.read(address, min(32, end - address)).hex()}


def symbolize_stop(payload, kit, stop):
    if stop.get('kernel_sha256') != sha256(payload):
        raise ValueError('Refuse symbolization against a different kernel image')
    sys.path.insert(0, str(kit))
    from kc_image import Image
    data = Path(payload).read_bytes()
    collection = Image(data)
    member = Image(data, collection.entries['com.apple.kernel'][1])
    tcr = int(stop['system_registers']['TCR_EL1'], 0)
    va_bits = 64 - ((tcr >> 16) & 63)
    if not 32 <= va_bits <= 52:
        raise ValueError('Unsupported captured kernel VA width')
    starts = member.function_starts()
    names = member.symbols()
    view = SimpleNamespace(base=member.base, segments=member.segments, read=member.read,
                           function_starts=lambda: starts, symbols=lambda: names)
    addresses = {'pc': stop.get('pc'), 'lr': stop.get('x30'),
                 'exception_pc': stop['system_registers'].get('ELR_EL1')}
    addresses.update({f'frame_{index}_lr': frame.get('lr')
                      for index, frame in enumerate(stop.get('frame_chain') or [])})
    return {'kernel_sha256': stop['kernel_sha256'], 'kernel_va_bits': va_bits,
            'addresses': {name: symbolize_function(view, int(value, 0), va_bits)
                          for name, value in addresses.items() if value}}


def seal(candidate, sealer, boot_args, profile):
    env = dict(os.environ, UNIXNU_XNU_ARCH=profile['os']['arch'],
               UNIXNU_IOS_VERSION=profile['os']['ios_version'])
    return subprocess.run([sys.executable, '-B', str(sealer), str(candidate), '--kernel-args', boot_args],
                          env=env, capture_output=True, text=True)


def cmd_emit(args):
    work = args.work.resolve()
    device = args.device.resolve()
    mainline = args.mainline.resolve()
    kit = work / 'tree/kits/XnuPrelink'
    logs = args.logs
    logs.mkdir(parents=True, exist_ok=True)
    board = load_board(device)
    profile, spec = load_spec(device, board)
    native = work / 'tree' / spec['kernel']
    cache = find_kernelcache(mainline)
    expected = spec.get('kernelcache_sha256')
    if expected and sha256(cache) != expected:
        raise SystemExit('extracted kernelcache does not match the qualified sha256')
    output = work / 'experimental/kernel.macho'
    output.parent.mkdir(parents=True, exist_ok=True)
    command = emit_command(spec, cache, output)
    log = logs / 'experimental-prelink.log'
    with log.open('w') as stream:
        stream.write(' '.join(command) + '\n')
        stream.flush()
        done = subprocess.run(command, cwd=work / 'tree', stdout=stream, stderr=subprocess.STDOUT)
    report_path = output.with_suffix('.json')
    record = {'command': command, 'exit_code': done.returncode, 'native': str(native),
              'kernelcache': str(cache), 'kernelcache_sha256': sha256(cache),
              'reference': str(work / 'tree' / spec['extra_args'][spec['extra_args'].index('--fileset-reference') + 1]),
              'candidate': str(output), 'allow_missing': True}
    if not report_path.is_file():
        record.update(status='no report', kernel_report_written=False)
        (logs / 'experimental-candidate.json').write_text(json.dumps(record, indent=2) + '\n')
        return 1
    shutil.copyfile(report_path, logs / 'experimental-prelink.json')
    report = json.loads(report_path.read_text())
    counts = unresolved(report)
    record.update(counts, mapping_complete=report.get('mapping_complete'),
                  candidate_written=report.get('candidate_written'),
                  stub_symbol=report.get('stub_symbol'),
                  early_security_init=report.get('early_security_init'))
    if not output.is_file():
        record.update(status='candidate not written')
        (logs / 'experimental-candidate.json').write_text(json.dumps(record, indent=2) + '\n')
        return 1
    boot_args = ' '.join(board['payload']['kernel_args'])
    sealer = mainline / 'scripts/seal-source-crypto-kernel.py'
    sealed = seal(output, sealer, boot_args, profile)
    (logs / 'experimental-seal.log').write_text(sealed.stdout + sealed.stderr)
    record.update(status='sealed' if sealed.returncode == 0 else 'seal failed',
                  seal_exit_code=sealed.returncode, boot_args=boot_args,
                  candidate_sha256=sha256(output), checkpoints=checkpoint_addresses(output, kit))
    record['boot_traces'], record['boot_observers'] = boot_observer_addresses(output, kit)
    (logs / 'experimental-candidate.json').write_text(json.dumps(record, indent=2) + '\n')
    print(json.dumps(record, indent=2))
    return 0 if sealed.returncode == 0 else 1


def find_loader(candidates, patterns=()):
    for path in candidates:
        if path.is_file():
            return path
    for pattern in patterns:
        for path in sorted(Path(pattern[0]).glob(pattern[1])):
            if path.is_file():
                return path
    return None


def cmd_boot(args):
    work = args.work.resolve()
    device = args.device.resolve()
    mainline = args.mainline.resolve()
    logs = args.logs
    logs.mkdir(parents=True, exist_ok=True)
    board = load_board(device)
    profile, spec = load_spec(device, board)
    record = json.loads((logs / 'experimental-candidate.json').read_text())
    candidate = Path(record['candidate'])
    summary = {'status': 'skipped', 'candidate': str(candidate), 'allow_missing': True}
    if record.get('status') != 'sealed' or not candidate.is_file():
        summary['reason'] = 'no sealed allow-missing candidate: ' + str(record.get('status'))
        (logs / 'qemu-boot.json').write_text(json.dumps(summary, indent=2) + '\n')
        return 0
    uefi = find_loader([work / 'package/Build/Out/AARCH64-DEBUG/UniXNU.efi',
                        work / 'tree/package/Build/Out/AARCH64-DEBUG/UniXNU.efi'])
    darwinboot = find_loader(
        [work / 'tree/drivers/DarwinBoot/build/DarwinBoot/DEBUG_CLANGPDB/AARCH64/DarwinBoot.efi',
         work / 'tree/drivers/DarwinBoot/Build/DarwinBoot/DEBUG_CLANGPDB/AARCH64/DarwinBoot.efi'],
        [(work / 'tree/Build', '**/DarwinBoot.efi'),
         (work / 'tree/drivers/DarwinBoot', '**/DarwinBoot.efi')])
    firmware = args.firmware
    missing = [name for name, value in (('UniXNU.efi', uefi), ('DarwinBoot.efi', darwinboot),
                                        ('edk2 AAVMF code fd', firmware)) if not value]
    if missing:
        summary.update(reason='loader inputs absent: ' + ', '.join(missing))
        (logs / 'qemu-boot.json').write_text(json.dumps(summary, indent=2) + '\n')
        print(json.dumps(summary, indent=2))
        return 0
    summary.update(loader=str(uefi), darwinboot=str(darwinboot), firmware=str(firmware),
                   firmware_sha256=sha256(firmware))
    esp = work / 'esp'
    payload = esp / 'EFI/UniXNU/Payloads/kernel.macho'
    (esp / 'EFI/BOOT').mkdir(parents=True, exist_ok=True)
    (esp / 'EFI/UniXNU/Drivers').mkdir(parents=True, exist_ok=True)
    payload.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(uefi, esp / 'EFI/BOOT/BOOTAA64.EFI')
    shutil.copyfile(darwinboot, esp / 'EFI/UniXNU/Drivers/DarwinBoot.efi')
    shutil.copyfile(candidate, payload)
    boot_args = merged_boot_arguments(board['payload']['kernel_args'], args.kernel_arg)
    summary.update(base_boot_args=' '.join(board['payload']['kernel_args']),
                   boot_args=boot_args, diagnostic_overrides=args.kernel_arg,
                   runtime_qualified=False)
    # The payload is a copy. Keep the candidate and the handset arguments intact,
    # and seal the actual final payload bytes with the actual planned arguments.
    sealed = seal(payload, mainline / 'scripts/seal-source-crypto-kernel.py', boot_args, profile)
    (logs / 'qemu-seal.log').write_text(sealed.stdout + sealed.stderr)
    summary.update(payload_seal_exit_code=sealed.returncode, payload_sha256=sha256(payload))
    if sealed.returncode:
        summary.update(status='skipped', reason='QEMU payload POST seal failed')
        (logs / 'qemu-boot.json').write_text(json.dumps(summary, indent=2) + '\n')
        return 1
    adt = payload.with_suffix('.macho.adt')
    adt_command = [sys.executable, '-B', str(mainline / 'scripts/qemu-entry/make-dt.py'),
                   '--armvirt', '--armcpu', '--nvram-proxy', '--qemu-vmm-present',
                   '--osenvironment', 'main', '--crypto-hash-method', 'sha2-384',
                   '--owned-memory-size', '0x20000000', '--dram-size', '0x100000000',
                   '--amfi-platform-only', '--output', str(adt)]
    adt_done = subprocess.run(adt_command, capture_output=True, text=True)
    (logs / 'qemu-adt.log').write_text(adt_done.stdout + adt_done.stderr)
    summary['adt_exit_code'] = adt_done.returncode
    if adt_done.returncode:
        summary.update(status='skipped', reason='make-dt.py failed')
        (logs / 'qemu-boot.json').write_text(json.dumps(summary, indent=2) + '\n')
        return 0
    (esp / 'EFI/UniXNU/unixnu.toml').write_text(
        'version = 1\n[boot]\ntimeout = 1\ndefault = "native"\n[kits]\nautoload = false\n'
        '[[driver]]\npath = "Drivers/DarwinBoot.efi"\n'
        '[[entry]]\nid = "native"\ntitle = "Native arm64e XNU - not SpringBoard"\n'
        'type = "xnu"\npath = "Payloads/kernel.macho"\nargs = "' + boot_args + '"\n')
    summary['boot_args'] = boot_args
    serial = logs / 'qemu-serial.log'
    serial.unlink(missing_ok=True)
    qemu = shutil.which('qemu-system-aarch64')
    if not qemu:
        summary.update(status='skipped', reason='qemu-system-aarch64 not installed')
        (logs / 'qemu-boot.json').write_text(json.dumps(summary, indent=2) + '\n')
        return 0
    command = [qemu, '-M', 'virt,gic-version=3', '-cpu', 'max,pauth=on', '-m', '4096', '-smp', '1',
               '-display', 'none', '-monitor', 'none', '-nic', 'none', '-no-reboot',
               '-serial', f'file:{serial}', '-device', 'ramfb',
               '-drive', f'if=pflash,format=raw,readonly=on,file={firmware}']
    variables = Path(firmware).with_name('edk2-arm-vars.fd')
    if variables.is_file():
        shutil.copyfile(variables, work / 'vars.fd')
        command += ['-drive', f'if=pflash,format=raw,file={work / "vars.fd"}']
        summary['variables_fd'] = str(variables)
    command += ['-drive', f'if=none,id=esp,format=raw,readonly=on,file=fat:{esp}',
                '-device', 'virtio-blk-pci,drive=esp']
    (logs / 'qemu-command.log').write_text(' '.join(command) + '\n')
    try:
        run = subprocess.run(command, capture_output=True, text=True, timeout=args.timeout)
        summary['exit_code'] = run.returncode
    except subprocess.TimeoutExpired:
        summary['exit_code'] = 'timeout'
    summary['serial_bytes'] = serial.stat().st_size if serial.is_file() else 0
    helper = mainline / 'scripts/qemu-entry/gdb-stop.py'
    reached = {}
    for name in CHECKPOINTS:
        address = (record.get('checkpoints') or {}).get(name)
        fixture = work / ('gdb-' + name.lstrip('_'))
        fixture.mkdir(parents=True, exist_ok=True)
        entry = {'address': address, 'fixture': str(fixture)}
        if not address:
            entry['result'] = 'symbol absent from candidate'
            reached[name] = entry
            continue
        stop_command = [sys.executable, '-B', str(helper), address, '--esp', str(esp),
                        '--kernel', str(payload), '--fixture', str(fixture),
                        '--gic-version', '3', '--qemu-memory-mib', '4096',
                        '--system-registers', '--capture-screen', '--qemu-ramfb',
                          '--firmware', str(firmware), '--timeout', str(args.gdb_timeout)]
        stop_command += checkpoint_guard_options(address, record.get('checkpoints') or {})
        for observer in (record.get('boot_observers') or {}).values():
            stop_command += ['--read-memory', observer['address'] + ':' + hex(observer['bytes'])]
        if name == '_IOFindBSDRoot':
            for trace in (record.get('boot_traces') or {}).values():
                stop_command += ['--trace-address', trace]
        (fixture / 'command.json').write_text(json.dumps(stop_command, indent=2) + '\n')
        done = subprocess.run(stop_command, capture_output=True, text=True)
        entry['exit_code'] = done.returncode
        report = fixture / 'gdb-stop.json'
        failure = fixture / 'gdb-failure.json'
        if report.is_file():
            data = json.loads(report.read_text())
            identity_matches = data.get('kernel_sha256') == summary['payload_sha256']
            stopped = identity_matches and data.get('pc') == address
            entry.update(stopped_at_checkpoint=stopped, pc=data.get('pc'),
                         interrupted=data.get('bounded_timeout_interrupted'),
                         cpu_model=data.get('qemu_cpu_model'),
                           argument_memory=data.get('argument_memory'))
            entry['actual_checkpoint'] = next((symbol for symbol, target in
                                               (record.get('checkpoints') or {}).items()
                                               if target and target == data.get('pc')), None) if identity_matches else None
            entry['same_guest_guard_hit'] = (entry['actual_checkpoint'] in STOP_GUARDS and not stopped)
            if entry['actual_checkpoint'] == '_panic':
                entry['decoded_panic'] = decode_kernel_timeout_panic(data)
            entry['boot_observers'] = record.get('boot_observers') or {}
            entry['observer_memory'] = data.get('memory') or {}
            if identity_matches:
                entry['observer_values'] = decode_boot_observers(entry['boot_observers'],
                                                                 entry['observer_memory'])
            else:
                entry['observer_error'] = 'Refuse observations from a different kernel image'
            entry['boot_trace_events'] = data.get('trace_events') or []
            shutil.copyfile(report, logs / f'qemu-{name.lstrip("_")}-stop.json')
            try:
                symbols = symbolize_stop(payload, work / 'tree/kits/XnuPrelink', data)
                (logs / f'qemu-{name.lstrip("_")}-symbols.json').write_text(json.dumps(symbols, indent=2) + '\n')
                entry['symbols'] = symbols['addresses']
            except (OSError, ValueError, KeyError) as error:
                entry['symbolization_error'] = str(error)
        if failure.is_file():
            entry['failure'] = json.loads(failure.read_text()).get('error')
            shutil.copyfile(failure, logs / f'qemu-{name.lstrip("_")}-failure.json')
        for extra in ('gdb-uart.log', 'screen.png'):
            source = fixture / extra
            if source.is_file():
                shutil.copyfile(source, logs / f'qemu-{name.lstrip("_")}-{extra}')
                if extra.endswith('.png'):
                    entry['screenshot'] = f'qemu-{name.lstrip("_")}-screen.png'
        reached[name] = entry
    panic_observations = [{'run_checkpoint': name, 'actual_checkpoint': entry['actual_checkpoint'],
                          'pc': entry['pc'], 'argument_memory': entry.get('argument_memory'),
                          'decoded_panic': entry.get('decoded_panic')}
                         for name, entry in reached.items()
                         if entry.get('actual_checkpoint') in ('_panic', '_Assert')]
    summary.update(status='ran', checkpoints=reached,
                    reached=[name for name, entry in reached.items() if entry.get('stopped_at_checkpoint')],
                    panic_observations=panic_observations,
                    panic_text=((panic_observations[0].get('decoded_panic') or {}).get('text') or
                                panic_observations[0]['argument_memory']) if panic_observations else None)
    (logs / 'qemu-boot.json').write_text(json.dumps(summary, indent=2) + '\n')
    print(json.dumps(summary, indent=2))
    return 0


def cmd_summary(args):
    logs = args.logs
    lines = []
    candidate = logs / 'experimental-candidate.json'
    if candidate.is_file():
        record = json.loads(candidate.read_text())
        lines.append(f"Experimental candidate: {record.get('status')} "
                     f"unresolved_references={record.get('references')} "
                     f"unique_targets={record.get('unique_targets')} "
                     f"bundles={record.get('bundles')} "
                     f"stubbed={record.get('stubbed_references')}")
        if record.get('candidate_sha256'):
            lines.append(f"- sealed candidate sha256 {record['candidate_sha256']}")
        for name, address in (record.get('checkpoints') or {}).items():
            lines.append(f"- checkpoint {name} {address}")
    boot = logs / 'qemu-boot.json'
    if boot.is_file():
        report = json.loads(boot.read_text())
        lines.append(f"QEMU: {report.get('status')} {report.get('reason', '')}".rstrip())
        if report.get('reached'):
            lines.append('Checkpoints reached: ' + ', '.join(report['reached']))
        for name, entry in (report.get('checkpoints') or {}).items():
            lines.append(f"- {name} {entry.get('address')}: stopped={entry.get('stopped_at_checkpoint')} "
                          f"actual={entry.get('actual_checkpoint')} pc={entry.get('pc')} "
                          f"cpu={entry.get('cpu_model')} error={entry.get('failure')}")
        if report.get('panic_text'):
            lines.append('Panic text: ' + json.dumps(report['panic_text'], ensure_ascii=False))
        screenshots = [entry['screenshot'] for entry in (report.get('checkpoints') or {}).values()
                       if entry.get('screenshot')]
        if screenshots:
            lines.append('Screenshots: ' + ', '.join(screenshots))
    print('\n'.join(lines))
    return 0


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command', choices=['emit', 'boot', 'summary'])
    parser.add_argument('--work', type=Path)
    parser.add_argument('--mainline', type=Path)
    parser.add_argument('--device', type=Path)
    parser.add_argument('--logs', required=True, type=Path)
    parser.add_argument('--firmware', type=Path, help='AAVMF/edk2 AArch64 code FD')
    parser.add_argument('--timeout', type=float, default=150.0, help='raw QEMU boot seconds')
    parser.add_argument('--gdb-timeout', type=float, default=90.0)
    parser.add_argument('--kernel-arg', action='append', default=[],
                        help='QEMU-only kernel argument override (boot command only)')
    args = parser.parse_args()
    if args.kernel_arg and args.command != 'boot':
        parser.error('--kernel-arg only applies to the boot command')
    if args.command == 'summary':
        return cmd_summary(args)
    for name in ('work', 'mainline', 'device'):
        if getattr(args, name) is None:
            parser.error(f'--{name} is required for {args.command}')
    if args.command == 'emit':
        return cmd_emit(args)
    if args.firmware is None:
        parser.error('--firmware is required for boot')
    return cmd_boot(args)


if __name__ == '__main__':
    sys.exit(main())
