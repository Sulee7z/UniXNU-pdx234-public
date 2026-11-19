#!/usr/bin/env python3
"""Execute Sony shared-power and pinned official radio tests; audit D27 link inputs."""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import shutil
import subprocess
import sys

sys.dont_write_bytecode = True

ROOT = Path(__file__).resolve().parents[2]
BASE = Path("/mnt/e/UniXNU-sheng27-sony-20261113")


def sha(path):
    with Path(path).open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def run(command, log, cwd=None):
    r = subprocess.run(list(map(str, command)), cwd=cwd, capture_output=True, text=True, timeout=180)
    log.write_text(r.stdout + r.stderr)
    if r.returncode:
        raise RuntimeError(str(log) + ": " + (r.stdout + r.stderr)[-5000:])
    return r.stdout


def symbols(path, global_only=False):
    text = subprocess.check_output(["llvm-nm", *(["-g"] if global_only else []), str(path)], text=True)
    defined, refs, global_defs = set(), set(), set()
    for line in text.splitlines():
        p = line.split()
        if len(p) < 2 or line.endswith(":"):
            continue
        if p[-2] == "U":
            refs.add(p[-1])
        elif len(p) >= 3:
            defined.add(p[-1])
            if p[-2].isupper():
                global_defs.add(p[-1])
    return defined, refs, global_defs


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--build", type=Path, required=True)
    p.add_argument("--out", type=Path, required=True)
    p.add_argument("--kernel", type=Path, default=BASE / "native-sony-touch-066-002/native.macho")
    p.add_argument("--mainline", action="store_true", help="also execute original cfg80211/mac80211 lifecycle with simulated radio")
    args = p.parse_args()
    if args.out.exists():
        raise ValueError("preserve previous check")
    args.out.mkdir(parents=True)
    out = args.out.resolve()
    build = args.build.resolve()
    report = json.loads((build / "result.json").read_text())
    if not report["compiled"] or sha(report["archive"]) != report["sha256"]:
        raise ValueError("radio archive changed")
    for path, digest in report["objects"].items():
        if sha(path) != digest:
            raise ValueError("radio object changed: " + path)
    for path,digest in report["source_inputs"].items():
        if sha(path)!=digest:
            raise ValueError("board build source changed: "+path)
    sys.path.insert(0,str(ROOT/"ci"))
    from compile_dependencies import valid
    for path in report["compile_receipts"]:
        receipt=json.loads(Path(path).read_text())
        if not valid(receipt) or sha(receipt["object"])!=receipt["object_sha256"]:
            raise ValueError("board compiler dependency changed: "+path)
    cc = shutil.which("clang")
    commands = []

    def case(name, source_list, include, extra=()):
        target = out / name
        command = [cc, "-std=gnu11", "-O1", "-g", "-Wall", "-Wextra", "-Wno-unused-parameter", "-Wno-sign-compare",
                   "-Wno-macro-redefined", "-fsanitize=address,undefined", "-fno-omit-frame-pointer",
                   *["-I" + str(d) for d in include], *extra, *source_list, "-o", target]
        run(command, out / (name + ".compile.log"))
        output = run([target], out / (name + ".run.log"))
        commands.append({"name": name, "command": list(map(str, command)), "output": output,
                         "sources": {str(s): sha(s) for s in source_list}, "hardware_verified": False})

    case("sony-power", [ROOT / "drivers/SonyWcn/SonyWcnPower.c", ROOT / "tests/sony_wcn_power.c"], [ROOT / "drivers/SonyWcn"])
    spec=importlib.util.spec_from_file_location("sony_wcn_guards",ROOT/"tests/sony_wcn_guards.py")
    guards=importlib.util.module_from_spec(spec);spec.loader.exec_module(guards)
    gate_source=out/"generated-guards.cpp";gate_source.write_text(guards.source(build))
    gate_binary=out/"generated-guards"
    command=[shutil.which("clang++"),"-std=c++20","-O1","-g","-Wall","-Wextra","-Werror",
             "-Wno-tautological-pointer-compare","-fsanitize=address,undefined",str(gate_source),"-o",str(gate_binary)]
    run(command,out/"generated-guards.compile.log")
    output=run([gate_binary],out/"generated-guards.run.log")
    commands.append({"name":"production-startup-guards","command":command,"output":output,
                     "source_sha256":sha(gate_source),"extractor_sha256":sha(ROOT/"tests/sony_wcn_guards.py"),"hardware_verified":False})
    bt = build / "components/QcaBluetooth"
    for name, files in (("bt-runtime", ["src/qbt_core.c", "src/qbt_linux.c", "out/linux/btqca.c", "tests/runtime.c"]),
                        ("bt-geni", ["src/qbt_geni.c", "tests/geni.c"])):
        case(name, [bt / f for f in files], [bt / f for f in ("include", "src", "shim", "out/linux")])
    wifi = build / "components/Ath12kWifi"
    # Linux host only: glibc exposes loff_t through stdlib; isolate that typedef
    # before the component defines its own Linux ABI loff_t. All tested C and
    # headers remain byte-identical; errno values are the production Linux shim's.
    prelude = out / "linux-host.h"
    prelude.write_text('#define loff_t nw_host_libc_loff_t\n#include <stdlib.h>\n#include <sys/types.h>\n#undef loff_t\n'
                       '#include <string.h>\n'
                       'static inline int nw_host_memcmp(const void *a,const void *b,size_t n){return n?memcmp(a,b,n):0;}\n'
                       '#define memcmp nw_host_memcmp\n'
                       '#include "' + str(wifi / "shim/libc/errno.h") + '"\n')
    case("wifi-runtime", [wifi / f for f in ("tests/runtime_test.c", "shim/src/lx_rt.c", "src/nw_rfkill.c", "src/nw_device.c")],
         [wifi / f for f in ("shim/include", "include", "out/pinned")], ["-include", str(prelude)])
    # Native 24A446 control/event decoder: unmodified official test command.
    events = run([sys.executable, wifi / "tools/test-wireless-events.py"], out / "wifi-events.log")
    commands.append({"name": "wifi-events", "output": events,
                     "receipt": str(wifi / "out/wireless-event-test/report.json"),
                     "receipt_sha256": sha(wifi / "out/wireless-event-test/report.json"), "hardware_verified": False})
    if args.mainline:
        # Linux linker/host portability only. Production source is never edited.
        script = wifi / "tools/sony-test-mainline-runtime.py"
        fixture = out / "mainline_runtime_test.c"
        original_fixture = (wifi / "tests/mainline_runtime_test.c").read_text()
        old = 'static int config(struct ieee80211_hw *hw, u32 changed) { (void)hw; (void)changed; return 0; }'
        if original_fixture.count(old) != 1:
            raise ValueError("mainline simulated config callback anchor changed")
        fixture.write_text(original_fixture.replace(old,
            'static int config(struct ieee80211_hw *hw, int radio_idx, u32 changed) { (void)hw; (void)radio_idx; (void)changed; return 0; }'))
        original = (wifi / "tools/test-mainline-runtime.py").read_text()
        adapted = original.replace('flags = ["-std=gnu11",', 'flags = ["-include", ' + repr(str(prelude)) + ', "-std=gnu11",')
        adapted = adapted.replace('"-Wl,-dead_strip"', '"-Wl,--gc-sections"')
        adapted = adapted.replace('root / "out" / name if tree == "generated" else root / name',
                                  'root / "out" / name if tree == "generated" else Path(' + repr(str(fixture)) + ') if name == "tests/mainline_runtime_test.c" else root / name')
        adapted = adapted.replace('str(p.relative_to(root))', 'str(p)')
        if adapted == original:
            raise ValueError("mainline host adaptation anchors changed")
        script.write_text(adapted)
        output = run([sys.executable, script], out / "wifi-mainline.log")
        receipt = wifi / "out/mainline-runtime-test/report.json"
        commands.append({"name": "wifi-mainline", "output": output, "receipt": str(receipt), "receipt_sha256": sha(receipt),
                         "original_test_sha256": sha(wifi / "tools/test-mainline-runtime.py"), "linux_runner_sha256": sha(script),
                         "original_fixture_sha256":sha(wifi / "tests/mainline_runtime_test.c"),"fixture_sha256":sha(fixture),
                         "hardware_verified": False})
    board = json.loads((build / "board-inputs.json").read_text())
    expected = {"smpg5": 1000000, "ldob15": 1800000, "smpg2": 980000, "smpe4": 950000, "smpg4": 1350000, "smpg6": 1900000}
    actual = {v["resource"]: v["config"][0] for v in board["supplies"]["wifi"].values()}
    if actual != expected:
        raise ValueError("Sony supply mapping differs")
    assert board["uart_irq"] == 493 and board["uart_sid"] == 0x423
    assert [row["pins"] for row in board["uart_pins"]["active"]] == [["gpio76"], ["gpio77"], ["gpio78"], ["gpio79"]]
    assert [row["bias"] for row in board["uart_pins"]["active"]] == ["bias-disable", "bias-pull-down", "bias-pull-up", "bias-disable"]
    assert [row["bias"] for row in board["uart_pins"]["default"]] == ["bias-disable", "bias-pull-down", "bias-pull-up", "bias-pull-down"]
    assert board["perst"] == 94 and board["wake"] == 96 and board["wlan_enable"] == 80 and board["bt_enable"] == 81
    assert board["pcie_msi_provider"]["compatible"] == ["arm,gic-v3-its"]
    assert board["pcie_msi_provider"]["reg"] == [0x17140000,0x20000]
    sources = {name: (build / "source" / name).read_text() for name in ("WifiProbe.cpp", "WifiNet.cpp", "BluetoothProbe.cpp")}
    assert "qcom_rpmh_active_request" not in sources["WifiProbe.cpp"] and "kRails[]" not in sources["WifiProbe.cpp"]
    assert "kSonyPciePhy" in sources["WifiProbe.cpp"]
    assert "native_ufs_extra_stream != 0x1401" in sources["WifiProbe.cpp"]
    assert "kSonyUartActive" in sources["BluetoothProbe.cpp"] and "sony_wcn_bluetooth_dma_prepare" in sources["BluetoothProbe.cpp"]
    for command in report["commands"].values():
        flags = command["command"]
        assert "-fptrauth-function-pointer-type-discrimination" in flags
        i = flags.index("-fptrauth-block-descriptor-pointers")
        assert flags[i-1] == "-Xclang"
    for token in ("sizeof(assoc_event27) == 540", "sizeof(assoc_request27) == 656"):
        assert token in sources["WifiNet.cpp"]
    archives = [Path(report["archive"])]
    if report["wifi_core"]:
        core = report["wifi_core"]
        if sha(core["archive"]) != core["sha256"]:
            raise ValueError("Ath12k core archive changed")
        for path,digest in core["source_hashes"].items():
            if sha(path)!=digest:
                raise ValueError("Ath12k compiled source changed: "+path)
        for path in core["compile_receipts"]:
            receipt=json.loads(Path(path).read_text())
            if not valid(receipt) or sha(receipt["object"])!=receipt["object_sha256"]:
                raise ValueError("Ath12k compiler dependency changed: "+path)
        archives.append(Path(core["archive"]))
    native, _, native_global = symbols(args.kernel)
    available, refs, defined = set(native), set(), set()
    for archive in archives:
        d, u, g = symbols(archive)
        available |= d
        refs |= u
        defined |= g
    missing = sorted(refs - available)
    duplicates = sorted(native_global & defined)
    integration = {"kernel": str(args.kernel), "kernel_sha256": sha(args.kernel), "missing_native_symbols": missing,
                   "global_symbol_collisions": duplicates,
                   "private_native_symbols": sorted((refs & native) - native_global),
                   "strict_link_passed": False,
                   "notes": ["Use real private native definitions at final relink; never synthesize success providers",
                              "Sony VFS firmware reader is namespaced; existing storage loader is unchanged",
                             "New radio startup entries and platform provider require main-owned integration"]}
    result = {"passed": True, "sanitizers": ["address", "undefined"], "hardware_verified": False,
              "checks": commands, "board_inputs_sha256": sha(build / "board-inputs.json"), "integration": integration,
              "archives": {str(a): sha(a) for a in archives}, "build_receipt_sha256": sha(build / "result.json"),
              "association_verified": False, "pairing_verified": False,
               "sources": {str(p): sha(p) for p in [Path(__file__), *ROOT.glob("drivers/SonyWcn/*.*"), ROOT / "tests/sony_wcn_power.c",ROOT/"tests/sony_wcn_guards.py"] if p.is_file()}}
    (out / "result.json").write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps({"passed": True, "hardware_verified": False, "integration": integration}, indent=2))


if __name__ == "__main__":
    main()
