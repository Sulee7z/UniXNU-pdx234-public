"""Validate only the explicitly qualified, isolated native C overlays."""
from pathlib import Path
from recount_cpu_kinds import adapt_source as adapt_recount
from native_pac_policy import adapt_source as adapt_jop
from single_cluster_qos import adapt_source as adapt_single_cluster
from vfs_shutdown_diagnostic import adapt_cache, adapt_shutdown
from usb_console import ADAPTERS as USB_ADAPTERS


def validate_overlays(result, sha):
    if result.get('platform067'):
        from platform067.integration import validate
        validate(result['platform067'])
    if result.get('block_descriptor_abi'):
        from block_descriptor_abi import validate_record
        validate_record(result['block_descriptor_abi'])
    expected = {}
    if result.get('recount_sparse_kind_span'):
        expected['recount-sparse-cpu-kind-span'] = adapt_recount
    if result.get('native_jop_policy'):
        expected['upstream-native-default-jop'] = adapt_jop
    if result.get('single_cluster_qos'):
        expected['single-cluster-qos-fallback'] = adapt_single_cluster
    if result.get('vfs_shutdown_diagnostic'):
        expected['vfs-parent-release-diagnostic'] = adapt_cache
        expected['vfs-shutdown-request-diagnostic'] = adapt_shutdown
    if result.get('usb_console'):
        if not result.get('usb_sources') or any(sha(p) != digest for p, digest in result['usb_sources'].items()):
            raise ValueError('USB module/profile source identity changed')
        expected.pop('vfs-parent-release-diagnostic', None)
        expected.update(USB_ADAPTERS)
    if result.get('launchd_trace'):
        from launchd_trace import adapt_source, adapt_vfs
        if result.get('launchd_transport'):
            from launchd_transport_trace import adapt_source, adapt_vfs
        if result.get('launchd_shutdown'):
            from launchd_shutdown_trace import adapt_source, adapt_vfs
        expected.pop('vfs-parent-release-usb-diagnostic', None)
        expected['pid1-syscall-trace'] = adapt_source
        expected['vfs-pid1-context'] = adapt_vfs
    patches = result.get('native_source_patches', [])
    if result.get('audit_source_repairs'):
        from audit_source_repairs import ADAPTERS
        expected.update(ADAPTERS)
        if result.get('official_addon_size_067'):
            from platform067.arm64e.source import adapt_source
            expected['audit-d27-addon-reference'] = adapt_source
    if result.get('upstream_startup'):
        from upstream_startup import ADAPTERS
        expected.update(ADAPTERS)
    if result.get('framebuffer_call_trace'):
        from framebuffer_call_trace import adapt_source
        expected['framebuffer-call-trace'] = adapt_source
    if result.get('qemu_workloop_event_classification'):
        from qemu.workloop_event_classification import adapt_source
        expected['qemu-workloop-event-classification'] = adapt_source
    if result.get('official_upstream_parity'):
        from qemu.upstream_20261108_parity import ADAPTERS
        expected.update(ADAPTERS)
    if result.get('official_logging_067'):
        from platform067.arm64e.logging067.qualify import expected_adapters, validate
        validate(result['platform067_logging'])
        expected.update(expected_adapters())
    if not expected or len(patches) != len(expected) or {p.get('native_source_patch') for p in patches} != set(expected):
        raise ValueError('Unqualified native source change')
    for patch in patches:
        if (sha(patch['original_source']) != patch['original_source_sha256'] or
                sha(patch['source']) != patch['source_sha256'] or
                Path(patch['source']).read_text() != expected[patch['native_source_patch']](Path(patch['original_source']).read_text())):
            raise ValueError('Native source overlay differs from the qualified change')
