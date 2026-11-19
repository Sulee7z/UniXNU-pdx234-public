"""Qualify Sony hardware from the saved live FDT, never from sheng geometry."""
from __future__ import annotations
from pathlib import Path
import sys

from source import LIVE_SHA, sha


def qualify(snapshot: Path, dtb: Path, opps: list[tuple[int, ...]]) -> dict:
    if sha(dtb) != LIVE_SHA:
        raise ValueError('Require exact post066 live.dtb')
    sys.path.insert(0, str(snapshot / 'UniXNU/scripts'))
    from unixnu.devicetree import read_fdt
    def path(n):
        return path(n.parent).rstrip('/') + '/' + n.name if n.parent else '/'
    nodes = {path(n): n for n in read_fdt(dtb.read_bytes()).walk()}
    def cells(p, k):
        return nodes[p].cells(k)
    cpu = '/soc/qcom,cpufreq-hw'
    domains = [cells(f'/cpus/cpu@{i * 256:x}', 'qcom,freq-domain') for i in range(8)]
    if (cells(cpu, 'reg') != [0x17d91000, 0x1000, 0x17d92000, 0x1000, 0x17d93000, 0x1000] or
            nodes[cpu].strings('compatible') != ['qcom,cpufreq-epss'] or
            domains != [[cells(cpu, 'phandle')[0], d] for d in (0, 0, 0, 1, 1, 1, 1, 2)] or
            cells('/soc/qcom,dcvs/l3', 'reg') != [0x17d90000, 0x4000, 0x17d90100, 0xa0] or
            cells('/soc/qcom,dcvs/l3/sp', 'qcom,shared-offset') != [0x90]):
        raise ValueError('Sony EPSS topology differs from the official implementation')
    gpu = '/soc/qcom,kgsl-3d0@3d00000'
    ddr = cells(gpu, 'qcom,bus-table-ddr')
    bins = []
    for speedbin in nodes[gpu + '/qcom,gpu-pwrlevel-bins'].children:
        bins.append({(n.scalar('qcom,gpu-freq'), n.scalar('qcom,level'), ddr[n.scalar('qcom,bus-freq')])
                     for n in speedbin.children})
    common = sorted(set.intersection(*bins))
    if [tuple(o[:3]) for o in opps[1:]] != common:
        raise ValueError('Already-linked HFI table differs from live Sony common OPPs')
    mdp = '/soc/qcom,mdss_mdp@ae00000'
    # Vendor mdp_phys starts one page below the mainline DPU MDP window.
    if cells(mdp, 'reg')[:2] != [0xae00000, 0x84000]:
        raise ValueError('Sony MDP resource changed')
    interfaces = []
    for i in range(2):
        p = f'/soc/qcom,mdss_dsi_ctrl{i}@{0xae94000 + i * 0x2000:x}'
        names, regs = nodes[p].strings('reg-names'), cells(p, 'reg')
        at = names.index('mdp_intf_base') * 2
        interfaces.append(regs[at:at + 2])
    if interfaces != [[0xae36000, 0x300], [0xae37000, 0x300]]:
        raise ValueError('Sony DSI interface windows changed')
    panel = mdp + '/somc,1_panel'
    timings = []
    for n in nodes[panel + '/qcom,mdss-dsi-display-timings'].children:
        timings.append(dict(name=n.name, width_per_link=n.scalar('qcom,mdss-dsi-panel-width'),
                            height=n.scalar('qcom,mdss-dsi-panel-height'),
                            supported_hz=n.scalar('qcom,mdss-dsi-panel-framerate'),
                            horizontal=[n.scalar('qcom,mdss-dsi-' + k) for k in ('h-front-porch', 'h-pulse-width', 'h-back-porch')],
                            vertical=[n.scalar('qcom,mdss-dsi-' + k) for k in ('v-front-porch', 'v-pulse-width', 'v-back-porch')]))
    if not any(t['width_per_link'] == 822 and t['height'] == 3840 and t['supported_hz'] == 120 for t in timings):
        raise ValueError('Sony native-resolution 120 Hz timing missing')
    # DT support is not proof of the UEFI inherited mode, nor a mode switch.
    return dict(live_dtb=str(dtb), live_dtb_sha256=sha(dtb), cpu_domains=domains,
                epss_bases=['0x17d91000', '0x17d92000', '0x17d93000'], l3_base='0x17d90000', l3_vote='0x90',
                common_gpu_opps=common, mdp_resource=['0xae00000', '0x84000'],
                dsi_interface_resources=interfaces, sony_panel=panel, supported_timings=timings,
                panel_current_hz=None, panel_mode_switch=False, direct_scanout_allowed=False)
