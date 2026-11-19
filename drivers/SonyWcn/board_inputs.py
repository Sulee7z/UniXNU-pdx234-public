"""Read Sony's captured FDT, retaining supply, pin and PMU-map provenance."""
from __future__ import annotations

import hashlib
from pathlib import Path
import struct


class Fdt:
    def __init__(self, path: Path):
        raw = path.read_bytes()
        if len(raw) < 40:
            raise ValueError("short FDT")
        magic, total, off, strings, _, version, _, _, slen, size = struct.unpack_from(">10I", raw)
        if magic != 0xD00DFEED or total > len(raw) or version < 17 or off + size > total or strings + slen > total:
            raise ValueError("invalid FDT header")
        self.nodes: dict[str, dict[str, bytes]] = {}
        self.handles: dict[int, str] = {}
        stack: list[str] = []
        at, end = off, off + size
        while at < end:
            token = struct.unpack_from(">I", raw, at)[0]
            at += 4
            if token == 1:
                stop = raw.index(b"\0", at, end)
                name = raw[at:stop].decode("ascii")
                stack.append(name)
                at = (stop + 4) & ~3
                self.nodes["/".join(stack) or "/"] = {}
            elif token == 2:
                if not stack:
                    raise ValueError("unbalanced FDT")
                stack.pop()
            elif token == 3:
                length, nameoff = struct.unpack_from(">II", raw, at)
                at += 8
                if not stack or at + length > end or nameoff >= slen:
                    raise ValueError("invalid FDT property")
                stop = raw.index(b"\0", strings + nameoff, strings + slen)
                name = raw[strings + nameoff:stop].decode("ascii")
                path = "/".join(stack) or "/"
                self.nodes[path][name] = raw[at:at + length]
                if name == "phandle":
                    handle = struct.unpack(">I", raw[at:at + length])[0]
                    if handle in self.handles:
                        raise ValueError("duplicate phandle")
                    self.handles[handle] = path
                at = (at + length + 3) & ~3
            elif token == 4:
                continue
            elif token == 9:
                if stack:
                    raise ValueError("unclosed FDT")
                break
            else:
                raise ValueError(f"invalid FDT token {token}")
        self.sha256 = hashlib.sha256(raw).hexdigest()

    def cells(self, path: str, name: str) -> list[int]:
        data = self.nodes[path][name]
        if len(data) % 4:
            raise ValueError(f"unaligned cells: {path}/{name}")
        return list(struct.unpack(f">{len(data)//4}I", data))

    def strings(self, path: str, name: str) -> list[str]:
        return self.nodes[path][name].rstrip(b"\0").decode().split("\0")

    def unique(self, suffix: str) -> str:
        candidates = [p for p in self.nodes if p.endswith(suffix)]
        if len(candidates) != 1:
            raise ValueError(f"non-unique FDT node {suffix}: {candidates}")
        return candidates[0]


def resolve(path: Path) -> dict:
    f = Fdt(path)
    wlan = f.unique("/qcom,cnss-qca-converged/chip_cfg@1")
    bt = f.unique("/bt-qca-converged/bt_kiwi")
    pcie = f.unique("/qcom,pcie@1c00000")
    uart = f.unique("/qcom,qup_uart@898000")
    wrapper = uart.rsplit("/", 1)[0]
    supplies = {}
    for radio, node in (("wifi", wlan), ("bluetooth", bt)):
        entries = {}
        for key in f.nodes[node]:
            if not key.endswith("-supply"):
                continue
            handle, = f.cells(node, key)
            target = f.handles[handle]
            resource_node = target.rsplit("/", 1)[0]
            config_key = ("qcom," if not key.startswith("qcom,") else "") + key[:-7] + "-config"
            entries[key] = dict(phandle=handle, node=target,
                                resource=f.strings(resource_node, "qcom,resource-name")[0],
                                regulator=f.strings(target, "regulator-name")[0],
                                config=f.cells(node, config_key))
        supplies[radio] = entries
    pins = {}
    for state in (0, 1, 2, 3):
        rows = []
        for handle in f.cells(uart, f"pinctrl-{state}"):
            node = f.handles[handle]
            mux, config = node + "/mux", node + "/config"
            cfg = f.nodes[config]
            bias = next((x for x in ("bias-pull-up", "bias-pull-down", "bias-disable") if x in cfg), None)
            rows.append(dict(node=node, pins=f.strings(mux, "pins"),
                             function=f.strings(mux, "function")[0], bias=bias,
                             drive_ma=f.cells(config, "drive-strength")[0]))
        pins[f.strings(uart, "pinctrl-names")[state]] = rows
    phy = f.cells(pcie, "qcom,phy-sequence")
    if len(phy) % 3 or any(phy[i] >= 0x2000 or phy[i] % 4 for i in range(0, len(phy), 3)):
        raise ValueError("invalid Sony PCIe PHY sequence")
    regs = f.cells(pcie, "reg")
    msi_node=f.handles[f.cells(pcie,"msi-map")[1]]
    assert f.cells(wlan, "supported-ids") == [0x1107]
    assert f.cells(uart, "reg") == [0x898000, 0x4000]
    assert f.cells(wrapper, "iommus")[1] == 0x423
    # GIC cell 461 is SPI, so INTID = 461 + 32 = 493.
    assert f.cells(uart, "interrupts-extended")[1:4] == [0, 461, 4]
    return dict(schema=1, source=str(path), sha256=f.sha256, supplies=supplies,
                wifi_node=wlan, bluetooth_node=bt, uart_node=uart,
                uart_reg=f.cells(uart, "reg"), uart_irq=493, uart_sid=0x423,
                uart_pins=pins, pcie_reg=dict(zip(f.strings(pcie, "reg-names"),
                                               [regs[i:i+2] for i in range(0, len(regs), 2)])),
                pcie_iommu_map=f.cells(pcie, "iommu-map"), pcie_msi_map=f.cells(pcie, "msi-map"),
                pcie_msi_provider=dict(node=msi_node,compatible=f.strings(msi_node,"compatible"),reg=f.cells(msi_node,"reg")),
                pcie_phy=[phy[i:i+3] for i in range(0, len(phy), 3)],
                perst=f.cells(pcie, "perst-gpio")[1], wake=f.cells(pcie, "wake-gpio")[1],
                wlan_enable=f.cells(wlan, "wlan-en-gpio")[1],
                bt_enable=f.cells(bt, "qcom,bt-reset-gpio")[1],
                pmu_vreg_map=f.strings(wlan, "qcom,pmu_vreg_map"),
                pdc_init=f.strings(wlan, "qcom,pdc_init_table"),
                sleep_clock="PMK8550 gpio3 func1 (actual FDT alt_sleep_clk_default)")


def header(board: dict) -> str:
    rows = ",\n".join("    {%#x, %#x, %d}" % tuple(row) for row in board["pcie_phy"])
    configs = []
    for state in ("default", "active"):
        values = []
        for pin in board["uart_pins"][state]:
            if pin["drive_ma"] != 2:
                raise ValueError("UART drive strength changed")
            # Qualcomm Kalama pinctrl: qup2_se6_l0..l3 is function selector 1.
            function = 0 if pin["function"] == "gpio" else 1
            pull = {"bias-disable": 0, "bias-pull-down": 1, "bias-pull-up": 3}[pin["bias"]]
            values.append(pull | function << 2)
        configs.append("static constexpr uint32_t kSonyUart%s[4] = {%s};" % (state.title(), ",".join(map(str, values))))
    return ("/* SPDX-License-Identifier: BSD-2-Clause-Patent */\n"
            "/* Generated only from captured Sony live.dtb: " + board["sha256"] + " */\n"
            "#pragma once\n#include <stdint.h>\n"
            "struct SonyPhyWrite {uint16_t offset; uint32_t value, delay_us;};\n"
            "static constexpr SonyPhyWrite kSonyPciePhy[] = {\n" + rows + "\n};\n"
            + "\n".join(configs) + "\n")
