#!/usr/bin/env python3
"""Build pinned official radio cores plus Sony board deltas for the actual D27 ABI.

Never mutates a reference checkout. Output must be a new isolated directory.
"""
from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import sys
import tomllib

sys.dont_write_bytecode = True

ROOT = Path(__file__).resolve().parents[2]
DRIVER = ROOT / "drivers/SonyWcn"
BASE = Path("/mnt/e/UniXNU-sheng27-sony-20261113")
SNAPSHOTS = Path("/mnt/f/UniXNU-Port-artifacts/platform067-20261118")
PINS = {"sheng": "6c42e1055ffb3b335fda991190ad221edaa7af3c",
        "Ath12kWifi": "84e02e0c0a3354c341c76affef582c7c41883f1f",
        "QcaBluetooth": "fa528145aee3073c47533d74ea260eb2818b6b63"}
DAEMON_SHA = "cfd94854d0a2efd3ca4a2de6e55349f43fd0d274a4b8bfa9937f29d9f7208cb1"
PAC = ["-fptrauth-function-pointer-type-discrimination", "-Xclang", "-fptrauth-block-descriptor-pointers"]


def sha(path: Path) -> str:
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def run(command: list, *, cwd: Path | None = None, log: Path | None = None, timeout: int = 600, env=None):
    result = subprocess.run(list(map(str, command)), cwd=cwd, capture_output=True, text=True, timeout=timeout, env=env)
    if log:
        log.write_text(result.stdout + result.stderr)
    if result.returncode:
        raise RuntimeError(f"command failed ({result.returncode}), see {log}:\n" + (result.stdout + result.stderr)[-9000:])
    return result.stdout


def copy_component(source: Path, dest: Path):
    # Preserve source snapshots, including their ignored build products. Tools may
    # write deps/out only inside this private copy.
    shutil.copytree(source, dest, ignore=shutil.ignore_patterns(".git", "out", "deps", "__pycache__"))


def base_commands(record: Path):
    data = json.loads(record.read_text())
    command = list(data["command"])
    if sha(Path(command[0])) != data["dependency_compiler_sha256"]:
        raise ValueError("selected D27 compiler identity changed")
    if "-fptrauth-function-pointer-type-discrimination" not in command:
        raise ValueError("D27 type-discriminated PAC command required")
    target = [p for p in command if p.startswith("--target=")]
    if not target or any(not p.startswith("--target=arm64e-apple-ios27.") for p in target):
        raise ValueError("D27 arm64e iOS27 command required")
    cxx = list(command)
    # BSD-private transports must use the real selected BSD compile, not the
    # IOKit public mbuf typedef environment.
    bsd_record = BASE / "sources/UniXNU/out/pdx234/ios-27.0.1-24A446-iphone14/pdx234_sheng27_bulk/tree/build/xnu/ios-obj/DEVELOPMENT_ARM64_BCM2837/bsd/DEVELOPMENT/kern_exec.o.json"
    bsd = json.loads("[" + bsd_record.read_text().strip().rstrip(",") + "]")[0]
    c = list(bsd["arguments"])
    c[c.index(bsd["file"])] = data["source"]
    c[c.index("-include") + 1] = str(Path(bsd["directory"]) / "meta_features.h")
    c += ["-std=gnu11", "-I" + bsd["directory"], "-Wno-shadow-header", "-Wno-missing-include-dirs"]
    return data, cxx, c


def compile_source(source: Path, obj: Path, *, base: list, oldsource: str, cwd: Path, includes: list[Path], extra=None):
    command = list(base)
    command[command.index(oldsource)] = str(source)
    command[command.index("-o") + 1] = str(obj)
    if "-MF" in command:
        command[command.index("-MF") + 1] = str(obj.with_suffix(".d"))
    else:
        command += ["-MD", "-MF", str(obj.with_suffix(".d"))]
    command += [*PAC, *["-I" + str(p) for p in includes], *(extra or [])]
    obj.with_suffix(".command.json").write_text(json.dumps(command, indent=2) + "\n")
    run(command, cwd=cwd, log=obj.with_suffix(".log"), timeout=180)
    dep = obj.with_suffix(".d")
    paths = shlex.split(dep.read_text().replace("\\\n", "").partition(":")[2]) if dep.exists() else [str(source)]
    identity = {"dependency_schema":1,"dependency_compiler":command[0],"dependency_compiler_sha256":sha(Path(command[0])),
                "source":str(source),"object":str(obj),"command": command, "cwd": str(cwd), "object_sha256": sha(obj),
                "dependencies": {str((cwd / p).absolute()): sha((cwd / p).absolute()) for p in paths}}
    obj.with_name(obj.name+".dependencies.json").write_text(json.dumps(identity, indent=2) + "\n")
    return identity


def firmware_manifest(source: Path | None, daemon: Path | None, out: Path) -> dict:
    result = {"schema": 1, "wifi_ready": False, "bluetooth_ready": False,
              "wifi": [], "bluetooth": [], "daemon": None,
              "board_data_required": "Sony Android loaded kiwi/bdwlan.e31 (raw board data; not board-2 container)",
              "required": ["/vendor/firmware_mnt/image/kiwi/amss20.bin", "/vendor/firmware/kiwi/bdwlan.e31",
                           "/vendor/firmware/kiwi/regdb.bin", "Sony WCN7850 HCI patch TLV and NVM"],
              "missing": []}
    if source:
        data = json.loads(source.read_text())
        if data.get("device") != "XQ-DQ72" or data.get("schema") != 1:
            raise ValueError("Sony manifest schema/device mismatch")
        for kind in ("wifi", "bluetooth"):
            for entry in data.get(kind, []):
                path = (source.parent / entry["file"]).resolve()
                if not entry.get("android_source", "").startswith("/vendor/"):
                    raise ValueError("Android firmware provenance required")
                if path.stat().st_size != entry["size"] or sha(path) != entry["sha256"]:
                    raise ValueError("Sony firmware hash/size mismatch: " + str(path))
                name = entry["name"]
                if "/" in name or ".." in name or not name:
                    raise ValueError("firmware basename required")
                dest = out / "runtime/firmware" / ("ath12k/WCN7850/hw2.0" if kind == "wifi" else "qca") / name
                dest.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(path, dest)
                result[kind].append({**entry, "staged": str(dest)})
        names = {entry["name"] for entry in result["wifi"]}
        # A raw bdwlan.e31 must not be relabelled board-2.bin. The manifest must
        # identify a separately validated converted board-2 container.
        result["wifi_ready"] = {"amss.bin", "m3.bin", "board-2.bin"}.issubset(names) and bool(data.get("ath12k_board2_qualified"))
    if daemon:
        digest = sha(daemon)
        result["daemon"] = {"path": str(daemon), "sha256": digest, "expected": DAEMON_SHA,
                            "adapter_hash_matches": digest == DAEMON_SHA}
    if result["bluetooth"] and result["daemon"]:
        names = {entry["name"] for entry in result["bluetooth"]}
        result["bluetooth_ready"] = {"hmtbtfw20.tlv", "hmtnv20.bin"}.issubset(names) and result["daemon"]["adapter_hash_matches"]
    if not result["wifi_ready"]:
        result["missing"].append("Sony firmware + ath12k board-2 conversion/qualification")
    if not result["bluetooth_ready"]:
        result["missing"].append("Sony HCI patch/NVM and original D27 bluetoothd hash qualification")
    (out / "firmware-manifest.json").write_text(json.dumps(result, indent=2) + "\n")
    return result


def build_wifi_core(component: Path, out: Path, clang: str, llvm: Path):
    lock = json.loads((component / "tools/source-lock.json").read_text())
    # Official fetch follows branch names, then checks the pinned commit. A
    # moving releng branch can already have advanced. Select the exact revision
    # inside this build-owned copy; never change a reference checkout.
    for name in ("linux", "freebsd"):
        dep = component / "deps" / name
        if not dep.exists():
            dep.parent.mkdir(exist_ok=True)
            run(["git","clone","--depth","1","--filter=blob:none","--sparse","--no-checkout",lock[name]["url"],dep],
                log=out/(name+"-clone.log"))
            run(["git","-C",dep,"fetch","--depth","1","origin",lock[name]["commit"]],log=out/(name+"-pin-fetch.log"))
            run(["git","-C",dep,"checkout","--detach",lock[name]["commit"]],log=out/(name+"-pin-checkout.log"))
        if dep.exists() and run(["git", "-C", dep, "rev-parse", "HEAD"]).strip() != lock[name]["commit"]:
            if run(["git", "-C", dep, "status", "--porcelain"]).strip():
                raise ValueError("preserve modified dependency: " + str(dep))
            run(["git", "-C", dep, "fetch", "--depth", "1", "origin", lock[name]["commit"]], log=out / (name + "-pin-fetch.log"))
            run(["git", "-C", dep, "checkout", "--detach", lock[name]["commit"]], log=out / (name + "-pin-checkout.log"))
    run(["bash", component / "tools/fetch-sources.sh"], log=out / "wifi-fetch.log", timeout=600)
    run(["bash", component / "tools/prepare.sh"], log=out / "wifi-prepare.log", timeout=600)
    resource = run([clang, "-print-resource-dir"]).strip() + "/include"
    flags = ["-target", "arm64e-apple-ios27.0.0", "-mkernel", "-O2", "-g0", "-ffreestanding", "-fno-builtin", "-fno-common",
             "-fno-strict-aliasing", "-fwrapv", "-fno-stack-protector", "-Wno-incompatible-pointer-types", "-Wno-error",
             "-fno-delete-null-pointer-checks", "-mgeneral-regs-only", "-momit-leaf-frame-pointer", "-std=gnu11", "-w",
             "-DCONFIG_ATH12K_DEBUG", "-DCONFIG_CFG80211=1", "-DCONFIG_MAC80211=1", "-DCONFIG_MAC80211_STA_HASH_MAX_SIZE=0",
             '-DCONFIG_MAC80211_RC_DEFAULT=""', "-nostdinc", "-isystem", str(component / "shim/libc"), "-isystem", resource,
             "-include", "lx_pci.h", *PAC]
    flags += ["-I" + str(component / d) for d in ("shim/include", "include", "out/pinned", "src", "out")]
    target = out / "wifi-core";target.mkdir(exist_ok=True)
    jobs = []
    for line in (component / "tools/sources.txt").read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        tree, _, name = line.partition(":") if ":" in line else ("", "", line)
        directory = {"ath12k": "ath12k-src", "mhi": "mhi-src", "qmi": "os-src"}.get(tree, tree)
        src = component / "out" / directory / name if tree and tree != "generated" else component / "out" / name if tree else component / name
        extra = []
        if tree == "ath12k" or (not tree and name.startswith("src/")):
            extra += ["-I" + str(component / "out/ath12k-src"), "-I" + str(component / "out/ath12k-src/wifi7")]
        elif tree:
            extra += ["-I" + str(component / "out" / ("cfg80211" if tree == "generated" else directory))]
        if name.startswith("src/nw_cfg80211_"):
            extra = ["-I" + str(component / "out/cfg80211")]
        if name in ("src/nw_fils.c", "src/nw_crypto_mac80211.c"):
            extra += ["-I" + str(component / "out/mac80211")]
        if tree == "crypto" or name == "src/nw_crypto_mac80211.c":
            extra += ["-I" + str(component / "shim/crypto"), "-I" + str(component / "out/crypto")]
        if tree == "crypto" and name == "aes-siv.c":
            extra += ["-Daes_siv_encrypt=nw_aes_siv_encrypt", "-Daes_siv_decrypt=nw_aes_siv_decrypt"]
        obj = target / (("w7_" if "/wifi7/" in str(src) else tree + "_" if tree else "") + src.stem + ".o")
        jobs.append((src, obj, extra))

    def compile(job):
        src, obj, extra = job
        command = [clang, "-c", *extra, *flags, "-MD", "-MF", str(obj.with_suffix(".d")), str(src), "-o", str(obj)]
        obj.with_suffix(".command.json").write_text(json.dumps(command, indent=2) + "\n")
        run(command, log=obj.with_suffix(".log"), timeout=180)
        dep=obj.with_suffix(".d")
        paths=shlex.split(dep.read_text().replace("\\\n", "").partition(":")[2])
        identity={"schema":1,"dependency_schema":1,"command":command,"cwd":str(Path.cwd()),
                  "dependency_compiler":clang,"dependency_compiler_sha256":sha(Path(clang)),
                  "source":str(src),"object":str(obj),"object_sha256":sha(obj),
                  "dependencies":{str(Path(p).absolute()):sha(Path(p)) for p in paths}}
        obj.with_name(obj.name+".dependencies.json").write_text(json.dumps(identity,indent=2)+"\n")
        return obj

    with ThreadPoolExecutor(8) as pool:
        objects = list(pool.map(compile, jobs))
    # Reuse the consuming builder's exact public ABI set, namespace all internals.
    source = (out / "official-build-ath12k-wifi.py").read_text()
    begin, end = source.index("keep = {"), source.index("objs = [o for", source.index("keep = {"))
    namespace = {}
    exec(source[begin:end], {"__builtins__": {}}, namespace)
    keep = namespace["keep"]
    names = set()
    for obj in objects:
        for line in run([llvm / "llvm-nm", "-g", "--defined-only", obj]).splitlines():
            parts = line.split()
            if len(parts) == 3 and parts[2] not in keep:
                names.add(parts[2])
    mapping = target / "rename.txt"
    mapping.write_text("".join(f"{name} _nwk{name}\n" for name in sorted(names)))
    for obj in objects:
        run([llvm / "llvm-objcopy", "--redefine-syms=" + str(mapping), obj])
        # Compiler receipts also record the explicit postcompile namespace step.
        path=obj.with_name(obj.name+".dependencies.json")
        identity=json.loads(path.read_text())
        identity.update(raw_object_sha256=identity["object_sha256"],object_sha256=sha(obj),namespace_map_sha256=sha(mapping))
        path.write_text(json.dumps(identity,indent=2)+"\n")
    archive = out / "libSonyAth12kCore.a"
    run([llvm / "llvm-ar", "rcs", archive, *objects])
    result = {"archive": str(archive), "sha256": sha(archive), "objects": {str(p): sha(p) for p in objects}, "flags": flags,
              "source_hashes":{str(src):sha(src) for src,_,_ in jobs},
              "compile_receipts":[str(p.with_name(p.name+".dependencies.json")) for p in objects],
              "source_identity": json.loads((component / "out/source-identity.json").read_text()), "hardware_verified": False}
    (target / "result.json").write_text(json.dumps(result, indent=2) + "\n")
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--snapshots", type=Path, default=SNAPSHOTS)
    parser.add_argument("--dtb", type=Path, default=ROOT.parents[1] / "evidence/Xperia-XQ-DQ72/20261118-platform-post066-readonly-001/live.dtb")
    parser.add_argument("--record", type=Path, default=BASE / "display-source-009/build/native-legacy-display/CpuFreqProbe.o.dependencies.json")
    parser.add_argument("--firmware-manifest", type=Path)
    parser.add_argument("--bluetoothd", type=Path)
    parser.add_argument("--wifi-core", action="store_true", help="fetch locked Linux/FreeBSD/supplicant and compile production Ath12kWifi")
    parser.add_argument("--resume", action="store_true", help="continue this builder's own failed isolated directory")
    args = parser.parse_args()
    if args.out.exists() and not (args.resume and (args.out / "sony-wcn-build.json").exists()):
        raise ValueError("preserve existing build: " + str(args.out))
    if shutil.disk_usage(args.out.parent).free < 4 * 1024**3:
        raise ValueError("build reserve below 4GiB")
    args.out.mkdir(parents=True, exist_ok=True)
    out = args.out.resolve()
    marker=out / "sony-wcn-build.json"
    if marker.exists() and json.loads(marker.read_text()) != {"owner":str(Path(__file__).resolve()),"pins":PINS}:
        raise ValueError("isolated build directory belongs to another command/pin")
    marker.write_text(json.dumps({"owner": str(Path(__file__).resolve()), "pins": PINS}) + "\n")
    for name, pin in PINS.items():
        revision = run(["git", "-c", "safe.directory=*", "-C", args.snapshots / name, "rev-parse", "HEAD"]).strip()
        if revision != pin:
            raise ValueError(f"snapshot pin changed: {name} {revision}")
    board = load("sony_wcn_inputs", DRIVER / "board_inputs.py")
    resolved = board.resolve(args.dtb)
    (out / "board-inputs.json").write_text(json.dumps(resolved, indent=2) + "\n")
    (out / "SonyWcnBoard.h").write_text(board.header(resolved))
    adapter = load("sony_wcn_adapt", DRIVER / "adapt.py")
    component = out / "components";component.mkdir(exist_ok=True)
    for name in ("Ath12kWifi", "QcaBluetooth"):
        if not (component / name).exists():
            copy_component(args.snapshots / name, component / name)
    wifi, bt = component / "Ath12kWifi", component / "QcaBluetooth"
    source = out / "source";source.mkdir(exist_ok=True)
    official = args.snapshots / "sheng/package"
    generated = {"WifiProbe.cpp": adapter.wifi((official / "WifiProbe.cpp").read_text()),
                 "BluetoothProbe.cpp": adapter.bluetooth((official / "BluetoothProbe.cpp").read_text())}
    for name, text in generated.items():
        (source / name).write_text(text)
    for name in ("WifiNet.cpp", "WifiFirmware.c", "WifiFirmware.h", "BluetoothFirmware.c", "BluetoothFirmware.h",
                 "WifiPcieTables.h", "MhiBoot.h", "BootResetCore.h", "WifiScan.h", "WifiScanResult.h", "WifiScanPolicy.h",
                 "BluetoothHciTrace.h", "SmmuBypass.h", "AppsSmmuLock.h"):
        shutil.copyfile(official / name, source / name)
    for name in ("WifiFirmware.c", "BluetoothFirmware.c"):
        path = source / name
        path.write_text(adapter.once(path.read_text(), '#include <sys/vnode.h>', 'struct nameidata;\n#include <sys/vnode.h>'))
    # The older storage archive already exports its original VFS loader. Keep it
    # untouched and namespace this Sony-owned loader rather than collide at link.
    for name in ("WifiFirmware.c", "WifiFirmware.h", "WifiProbe.cpp"):
        path = source / name
        path.write_text(path.read_text().replace("sheng_wifi_firmware_read", "sony_wifi_firmware_read"))
    shutil.copyfile(args.snapshots / "sheng/scripts/build-ath12k-wifi.py", out / "official-build-ath12k-wifi.py")
    # Firmware callbacks retain the official VFS ownership. Data readiness is not
    # firmware qualification; these gates are generated from validated inputs.
    manifest = firmware_manifest(args.firmware_manifest, args.bluetoothd, out)
    (source / "SonyWcnQualification.c").write_text(
        '/* SPDX-License-Identifier: BSD-2-Clause-Patent */\n#include <sys/errno.h>\n'
        f'int sony_wcn_wifi_inputs_ready(void){{return {"0" if manifest["wifi_ready"] else "ENOENT"};}}\n'
        f'int sony_wcn_bluetooth_inputs_ready(void){{return {"0" if manifest["bluetooth_ready"] else "ENOENT"};}}\n')
    run([sys.executable, bt / "tools/prepare-linux.py"], log=out / "bt-linux.log")
    data, cxx, c = base_commands(args.record)
    cwd = next(Path(p).parent for p in data["dependencies"] if p.endswith("/meta_features.h"))
    llvm = Path(shutil.which("llvm-objcopy-23") or shutil.which("llvm-objcopy")).parent
    # Newly pinned SM8550 operations are source-consumed through the existing
    # selected SoC kit, not device-dependent sheng MMIO policy.
    feed = tomllib.loads((args.snapshots / "sheng/feeds.toml").read_text())["source"][0]
    socroot = component / "UniXNU-sm8550-common"
    if not socroot.exists():
        run(["git", "clone", "--no-checkout", "--filter=blob:none", feed["git"], socroot], log=out / "soc-clone.log")
        run(["git", "-C", socroot, "checkout", "--detach", feed["commit"]], log=out / "soc-checkout.log")
    if run(["git", "-C", socroot, "rev-parse", "HEAD"]).strip() != feed["commit"]:
        raise ValueError("SoC pin mismatch")
    soc = socroot / "kits/Sm8550Platform"
    smmu = BASE / "sources/UniXNU/out/pdx234/ios-27.0.1-24A446-iphone14/pdx234_sheng27_bulk/tree/drivers/ArmSmmu4K"
    # ArmSmmu4K is header-consumed by the SoC's QUP DMA implementation.
    if not smmu.exists():
        smmu = BASE / "gpu-source-006/kits/ArmSmmu4K"
    includes = [out, DRIVER, source, wifi / "include", bt / "include", bt / "src", bt / "shim", bt / "out/linux", soc, smmu]
    objects = out / "objects";objects.mkdir(exist_ok=True)
    jobs = [(source / "WifiProbe.cpp", cxx), (source / "WifiNet.cpp", cxx), (source / "BluetoothProbe.cpp", cxx),
            (DRIVER / "SonyWcnPlatform.cpp", cxx), (DRIVER / "SonyWcnPower.c", c),
            *[(source / name, c) for name in ("WifiFirmware.c", "BluetoothFirmware.c", "SonyWcnQualification.c")],
            *[(bt / name, c) for name in ("src/qbt_core.c", "src/qbt_linux.c", "src/qbt_geni.c", "src/qbt_transport.c", "out/linux/btqca.c")],
            *[(soc / name, c) for name in ("Sm8550GeniUart.c", "Sm8550Gcc.c", "Sm8550QupDma.c")]]
    receipts = {}
    for src, command in jobs:
        if not src.is_file():
            raise FileNotFoundError("selected SoC dependency absent: " + str(src))
        obj = objects / (src.stem + ".o")
        receipts[src.name] = compile_source(src, obj, base=command, oldsource=data["source"], cwd=cwd, includes=includes,
                                            extra=["-Wno-sign-compare", "-Wno-unused-function", "-Wno-unused-variable",
                                                   "-Wno-missing-field-initializers", "-Wno-missing-braces", "-Wno-deprecated-volatile", "-Wno-unused-but-set-global"])
    late = objects / "WifiNet.late.o"
    run([shutil.which("llvm-objcopy-23") or llvm / "llvm-objcopy", "--remove-section=__DATA,__mod_init_func", "--globalize-symbol=__GLOBAL__sub_I_WifiNet.cpp", objects / "WifiNet.o", late])
    shared_soc_names={"Sm8550Gcc.c","Sm8550QupDma.c"}
    members = [late, *[objects / (src.stem + ".o") for src, _ in jobs if src.name != "WifiNet.cpp" and src.name not in shared_soc_names]]
    soc_archive=out/"libSonyWcnSocQualification.a"
    run([llvm/"llvm-ar","rcs",soc_archive,*[objects/(Path(name).stem+".o") for name in sorted(shared_soc_names)]])
    # Resume may have old members. Build a new archive and atomically replace
    # only this builder's own artifact, never llvm-ar append stale members.
    archive = out / "libSonyWcn.a"
    temporary=out/"libSonyWcn.new.a"
    if temporary.exists():
        raise ValueError("preserve interrupted temporary archive")
    run([llvm / "llvm-ar", "rcs", temporary, *members])
    temporary.replace(archive)
    report = {"schema": 1, "compiled": True, "hardware_verified": False, "image_delivered": False,
              "archive": str(archive), "sha256": sha(archive), "pins": PINS,
              "entry_points": ["native_sony_wifi_start", "native_sony_bluetooth_start", "native_sony_bluetooth_publish", "sony_wcn_platform_install"],
              "command_record": str(args.record), "command_record_sha256": sha(args.record), "pac_flags": PAC,
              "objects": {str(p): sha(p) for p in members}, "commands": receipts,
              "soc_qualification_only":{"archive":str(soc_archive),"sha256":sha(soc_archive),
                                         "linked":False,"reason":"Do not introduce a separate clock/SMMU lock over existing Sony owners"},
              "board_inputs_sha256": sha(out / "board-inputs.json"), "firmware": manifest,
              "source_inputs": {str(p): sha(p) for p in [*DRIVER.glob("*.*"), *source.glob("*.*"),Path(__file__)] if p.is_file()}, "soc_pin": feed,
              "compile_receipts":[str(objects/(src.stem+".o.dependencies.json")) for src,_ in jobs],
              "wifi_core": None, "missing": ["shared platform RPMh/NoC/sleep-clock/GCC provider", "Sony PCIe0 GIC ITS MSI provider",
                                              "QUP2 SID0x423 DMA provider serialized with Sony touch", *manifest["missing"],
                                              "signed supplicant/BlueTool/Type0 runtime + D27 daemon/IOKit ABI and final startup-section qualification"]}
    if args.wifi_core:
        report["wifi_core"] = build_wifi_core(wifi, out, cxx[0], llvm)
    elif (out / "wifi-core/result.json").exists():
        core = json.loads((out / "wifi-core/result.json").read_text())
        if sha(Path(core["archive"])) != core["sha256"] or any(sha(Path(p)) != h for p, h in core["objects"].items()):
            raise ValueError("preserve changed existing Wi-Fi core")
        report["wifi_core"] = core
    (out / "result.json").write_text(json.dumps(report, indent=2) + "\n")
    archives=[str(archive)]+([report["wifi_core"]["archive"]] if report["wifi_core"] else [])
    fragment={"baseline_native_sha256":"80b2b18120eafde479aa2eaebd4017a677a67405b0ba0fe33e8d00ad6b6bc3dc",
              "startup_calls":["native_sony_wifi_start","native_sony_bluetooth_start"],
              "added_archives":archives,"member_replacements":[],"virtual_backends_selected":False,
              "compile_receipts":report["compile_receipts"]+(report["wifi_core"].get("compile_receipts",[]) if report["wifi_core"] else []),
              "inputs":{str(path):sha(Path(path)) for path in [out/"result.json",out/"board-inputs.json",out/"firmware-manifest.json",*archives]},
              "result_metadata":{"sony_wcn":{"build_receipt":str(out/"result.json"),"compiled":True,
                                              "hardware_verified":False,"missing":report["missing"]}},
              "runtime_arguments_qualified":False,"production_args_until_qualified":["wifi=0","bluetooth=0"]}
    (out/"integration-fragment.json").write_text(json.dumps(fragment,indent=2)+"\n")
    print(json.dumps({k: report[k] for k in ("compiled", "archive", "sha256", "hardware_verified", "missing")}, indent=2))


if __name__ == "__main__":
    main()
