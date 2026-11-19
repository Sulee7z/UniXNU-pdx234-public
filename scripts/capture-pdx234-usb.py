#!/usr/bin/env python3
"""Capture the PDX234 CDC log on Windows; receive only, no device commands."""
import argparse
import hashlib
import json
from pathlib import Path
import sys
import time


def select_port(ports, explicit):
    candidates = [p for p in ports if p.device.lower() == explicit.lower()] if explicit else [
        p for p in ports if p.vid == 0x1209 and p.pid == 0x316d and p.serial_number in ('PDX234XnuLog','PDX234UEFI01')]
    if len(candidates) > 1:
        raise ValueError('Multiple matching ports; choose --port COMn')
    return candidates[0] if candidates else None


def main():
    if hasattr(sys.stdout, 'reconfigure'):
        sys.stdout.reconfigure(errors='replace')
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--port', help='Explicit COM port, otherwise exact VID/PID/serial matching')
    parser.add_argument('--out', type=Path)
    parser.add_argument('--wait', type=float, default=180, help='Seconds to wait for enumeration')
    parser.add_argument('--seconds', type=float, default=600, help='Capture duration, 0 until Ctrl+C')
    parser.add_argument('--list', action='store_true')
    args = parser.parse_args()
    if args.wait < 0 or args.seconds < 0:
        parser.error('Durations must be nonnegative')
    try:
        import serial
        from serial.tools import list_ports
    except ImportError:
        parser.error('Install pyserial: py -m pip install pyserial')
    if args.list:
        for port in list_ports.comports():
            print(port.device, port.description, port.hwid, 'serial=' + str(port.serial_number))
        return
    if not args.out:
        parser.error('--out is required for capture')
    args.out.mkdir(parents=True, exist_ok=False)
    events = []
    record = dict(serials=['PDX234XnuLog','PDX234UEFI01'], vid='1209', pid='316d', receive_only=True,
                  device_commands_sent=False, events=events, panic_end_seen=False)
    raw_path = args.out / 'usb.raw.log'
    deadline = time.monotonic() + args.wait
    print('Waiting for PDX234 UEFI/XNU CDC with USB connected.', flush=True)
    connection = None
    began = None
    tail = b''
    try:
        with raw_path.open('xb') as raw:
            while True:
                now = time.monotonic()
                if began is not None and args.seconds and now - began >= args.seconds:
                    break
                if connection is None:
                    if now >= deadline:
                        record['stop_reason'] = 'enumeration/reconnect timeout'
                        break
                    port = select_port(list_ports.comports(), args.port)
                    if port is None:
                        time.sleep(0.2)
                        continue
                    try:
                        connection = serial.Serial(port.device, 115200, timeout=0.2)
                        connection.dtr = True
                    except (serial.SerialException, OSError) as error:
                        if connection:
                            connection.close()
                            connection = None
                        events.append(dict(time=time.time(), event='open failed', error=str(error)))
                        time.sleep(0.2)
                        continue
                    if began is None:
                        began = now
                    events.append(dict(time=time.time(), event='connected', port=port.device, hwid=port.hwid,
                                       serial=port.serial_number,stage='UEFI' if port.serial_number=='PDX234UEFI01' else 'XNU'))
                    print('Connected:', port.device, flush=True)
                try:
                    data = connection.read(65536)
                except (serial.SerialException, OSError) as error:
                    events.append(dict(time=time.time(), event='disconnected', error=str(error)))
                    connection.close()
                    connection = None
                    deadline = time.monotonic() + args.wait
                    continue
                if data:
                    raw.write(data)
                    raw.flush()
                    sys.stdout.write(data.decode('utf-8', errors='replace'))
                    sys.stdout.flush()
                    joined = tail + data
                    if b'QCOM PANIC END' in joined:
                        record['panic_end_seen'] = True
                    tail = joined[-64:]
    except KeyboardInterrupt:
        record['stop_reason'] = 'Ctrl+C'
    finally:
        if connection:
            connection.close()
        data = raw_path.read_bytes() if raw_path.exists() else b''
        record.update(bytes=len(data), sha256=hashlib.sha256(data).hexdigest(),
                      duration_s=time.monotonic() - began if began else 0)
        (args.out / 'capture.json').write_text(json.dumps(record, indent=2) + '\n', encoding='utf-8')
        (args.out / 'usb.txt').write_text(data.decode('utf-8', errors='replace'), encoding='utf-8')
        print('\nSaved:', raw_path, 'bytes=', len(data))
    if not record['bytes']:
        raise SystemExit(2)


if __name__ == '__main__':
    main()
