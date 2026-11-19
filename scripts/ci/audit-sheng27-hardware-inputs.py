#!/usr/bin/env python3
"""Classify sheng27 peripheral initializers by Sony evidence and current inputs."""
import json
import argparse
from pathlib import Path
import subprocess

BASE=Path('/mnt/e/UniXNU-sheng27-sony-20261113')

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out',type=Path,required=True)
    args=parser.parse_args()
    sheng=BASE/'sources/sheng/package';sony=BASE/'sources/sony';result=[]
    rows={
      'sheng_cpufreq_probe':('CpuFreqProbe.cpp','Sony live DT EPSS domains, 3/4/1 topology, L3 window and vote 0x90 match; display-source-007 and boot-screen-004 linked','compiled and polling restored; clock/LUT hardware observation pending'),
      'sheng_thermal_probe':('ThermalProbe.cpp','Sony thermal sensors/policy mapping not pinned','do not enable'),
      'sheng_thermal_level_probe':('ThermalLevel.cpp','Sony thermal level inputs not pinned','do not enable'),
      'sheng_board_clock_probe':('BoardClock.cpp','Sony clock board mapping not pinned','do not enable'),
      'sheng_gpu_pool_probe':('GpuMemoryPool.cpp','GPU disabled in software control; source needs Sony memory policy','defer with GPU'),
      'sheng_adsp_probe':('AdspProbe.cpp','Sony ADSP firmware/input not qualified','do not enable'),
      'sheng_audio_probe':('AudioProbe.cpp','Sony audio path not qualified','do not enable'),
      'sheng_battery_probe':('BatteryProbe.cpp','Sony battery transport not qualified','do not enable'),
      'sheng_backlight_probe':('BacklightProbe.cpp','Sony panel/backlight ABI not qualified','do not enable'),
      'sheng_dpu_probe':('DisplayTimingProbe.cpp','Sony DPU registers and active pipe state require comparison with sheng','comparison pending'),
      'sheng_usb_probe':('UsbProbe.cpp','sheng QcomDwc3 path requires Sony PHY/rails mapping; separate CDC is failing reset','do not enable'),
      'sheng_wifi_probe':('WifiProbe.cpp','Sony WCN firmware/transport not qualified','do not enable'),
      'sheng_bluetooth_probe':('BluetoothProbe.cpp','Sony Bluetooth transport not qualified','do not enable'),
      'native_hid_input_probe':('HidInputProbe.cpp','Sony touch controller transport not implemented; D27 HID family only','do not enable'),
      'native_touch_probe':('TouchProbe.cpp','Two retained input-devices captures identify lxs_ts_input at i2c-2/2-0028; enabled DT lxs,sw82907 under I2C GENI 0xa90000, 400 kHz, coordinates 1644x3840','implement SW82907 transport/report decoding; sheng Novatek SPI path is incompatible'),
      'sheng_buttons_probe':('ButtonProbe.cpp','Sony button input mapping not qualified','do not enable'),
      'sheng_keyboard_probe':('KeyboardProbe.cpp','Sony has no sheng keyboard cover input','do not enable'),
      'sheng_software_aes_probe':('SoftwareAesProbe.cpp','macOS-only weak source in Sony iOS build','not applicable'),
      'sheng_ethernet_probe':('ShengEthernet.cpp','macOS-only weak source','not applicable'),
      'sheng_video_probe':('VideoProbe.cpp','Sony video hardware path not qualified','do not enable')}
    for symbol,(source,evidence,decision) in rows.items():
        p=sheng/source;result.append(dict(symbol=symbol,source=str(p),source_exists=p.exists(),evidence=evidence,decision=decision,
            source_copy_present=(sony/'package'/source).is_file(),hardware_comparison_complete=False))
    report=dict(sheng_commit='1108068537d5396edb2c63b2f8c6f5b97b0a4bbc',sony_inputs='D27/PDX234',rows=result,
        current_release_cpu_present=True,hardware_verified=False)
    args.out.write_text(json.dumps(report,indent=2)+'\n');print('Wrote',len(result),'preliminary hardware classifications to',args.out)

if __name__=='__main__':main()
