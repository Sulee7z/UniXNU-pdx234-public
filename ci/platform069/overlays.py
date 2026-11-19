"""Compose069 source qualifiers without editing any frozen067 helper/receipt."""
import json
from pathlib import Path

from native_source_overlays import validate_overlays as validate_inherited
from platform069.integration import BASELINE_SHA,expected_adapters,validate


def validate_overlays(result,sha):
    if not result.get('platform069'):return validate_inherited(result,sha)
    record=result['platform069'];validate(record)
    baseline_path=Path(record['baseline_result'])
    if record['inputs'].get(str(baseline_path))!=sha(baseline_path):raise ValueError('Missing immutable069 baseline receipt')
    baseline=json.loads(baseline_path.read_text())
    if baseline['native_sha256']!=BASELINE_SHA:raise ValueError('Wrong source qualification baseline')
    validate_inherited(baseline,sha)
    if result.get('platform067')!=baseline.get('platform067'):
        raise ValueError('Inherited067 provenance cannot be rewritten')
    # An inherited policy cannot be disabled to avoid its source checks.
    for key in ('audit_source_repairs','upstream_startup','official_upstream_parity','official_logging_067',
                'official_addon_size_067','recount_sparse_kind_span','single_cluster_qos','native_jop_policy',
                'vfs_shutdown_diagnostic','usb_console','launchd_trace','launchd_transport','launchd_shutdown',
                'framebuffer_call_trace','qemu_workloop_event_classification'):
        if result.get(key)!=baseline.get(key):raise ValueError('Inherited source policy changed: '+key)
    adapters=expected_adapters(record)
    inherited={row['native_source_patch']:row for row in baseline['native_source_patches']}
    patches=result['native_source_patches'];selected={row['native_source_patch']:row for row in patches}
    if len(selected)!=len(patches) or set(selected)!=set(inherited)|set(adapters):
        raise ValueError('Missing, duplicate or unqualified069 native source overlay')
    for name,row in selected.items():
        if name not in adapters:
            if row!=inherited[name]:raise ValueError('Unqualified mutation of inherited source overlay: '+name)
            continue
        if (sha(row['source'])!=row['source_sha256'] or
                sha(row['original_source'])!=row['original_source_sha256'] or
                Path(row['source']).read_text()!=adapters[name](Path(row['original_source']).read_text())):
            raise ValueError('069 source differs from its exact qualified adapter: '+name)
        if name in inherited and any(row[key]!=inherited[name][key] for key in ('original_source','original_source_sha256')):
            raise ValueError('Cannot change an inherited source overlay original identity')
    from block_descriptor_abi import validate_record
    validate_record(result['block_descriptor_abi'])


def run_inherited_main(filename):
    """Reuse the frozen strict/instruction checker with this stricter source gate.

    Its ELF/Mach-O, closure, PAC, missing-symbol and memory-layout checks run
    unchanged. Only the source gate is dispatched here for069; the filesystem
    helpers and all historical input hashes remain byte-identical.
    """
    import importlib.util
    import native_source_overlays
    original=native_source_overlays.validate_overlays
    native_source_overlays.validate_overlays=validate_overlays
    try:
        spec=importlib.util.spec_from_file_location('frozen069_'+filename.stem,filename)
        module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);module.main()
    finally:native_source_overlays.validate_overlays=original
