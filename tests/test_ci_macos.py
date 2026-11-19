import importlib.util
import hashlib
import json
import os
from pathlib import Path
import shutil
import struct
import subprocess
import sys
import unittest
import tempfile
from unittest.mock import patch
from types import SimpleNamespace

DEVICE=Path(__file__).resolve().parents[1]
PATH=DEVICE/'scripts/ci/collect-macos-logs.py'
spec=importlib.util.spec_from_file_location('collect_macos',PATH)
collector=importlib.util.module_from_spec(spec)
spec.loader.exec_module(collector)
prepare_spec=importlib.util.spec_from_file_location('prepare_macos',DEVICE/'scripts/ci/prepare-macos.py')
prepare=importlib.util.module_from_spec(prepare_spec)
prepare_spec.loader.exec_module(prepare)
bringup_spec=importlib.util.spec_from_file_location('qemu_bringup',DEVICE/'scripts/ci/qemu-bringup.py')
bringup=importlib.util.module_from_spec(bringup_spec)
bringup_spec.loader.exec_module(bringup)
reference_spec=importlib.util.spec_from_file_location('verify_reference',DEVICE/'scripts/ci/verify-fileset-reference.py')
reference=importlib.util.module_from_spec(reference_spec)
reference_spec.loader.exec_module(reference)


class MacosWorkflowTests(unittest.TestCase):
    def test_collection_member_repeats_cpu_capability_bits(self):
        sys.path.insert(0,str(DEVICE/'ci/XnuPrelink'))
        from fileset_segmented import mirror_member_subtype
        data=bytearray(128)
        struct.pack_into('<II',data,4,0x100000c,0xc0000002)
        struct.pack_into('<II',data,68,0x100000c,0x80000002)
        info=mirror_member_subtype(data,64)
        self.assertEqual(struct.unpack_from('<I',data,72)[0],0xc0000002)
        self.assertEqual(info['native'],'0x80000002')
        struct.pack_into('<I',data,68,0x1000007)
        with self.assertRaisesRegex(ValueError,'cputype differs'):
            mirror_member_subtype(data,64)

    def test_timeout_panic_uses_captured_stack_arguments(self):
        values=[0x1000,0x2000,123,456,0x3000]
        stop={'argument_memory':{'x0':'%s %s (start: %llu, end: %llu)%s', 'x1':'wrong register'},
              'stack_bytes':struct.pack('<5Q',*values).hex(),
              'stack_pointer_memory':{str(i):{'address':hex(values[i]),'bytes':text.encode().hex()+'00'}
                                      for i,text in ((0,'preemption disable timeout exceeded:'),
                                                     (1,'1.934 ms >= 1.920 ms'),(4,''))}}
        decoded=bringup.decode_kernel_timeout_panic(stop)
        self.assertEqual(decoded['reason'],'preemption disable timeout exceeded:')
        self.assertEqual(decoded['start'],123)
        self.assertEqual(decoded['end'],456)
        stop['stack_pointer_memory']['0']['address']='0x9999'
        self.assertIsNone(bringup.decode_kernel_timeout_panic(stop))
        self.assertIsNone(bringup.decode_kernel_timeout_panic({'argument_memory':{'x0':'different format'}}))

    def test_root_probe_catches_assert_and_panic_in_the_same_guest(self):
        points={'_IOFindBSDRoot':'0x1000','_panic':'0x2000',
                '_Assert':'0x3000','_unixnu_fileset_unmapped':'0x4000'}
        options=bringup.checkpoint_guard_options('0x1000',points)
        self.assertEqual(options,['--also-stop','0x2000','--also-stop','0x3000',
                                  '--also-stop','0x4000'])
        self.assertNotIn('0x2000',bringup.checkpoint_guard_options('0x2000',points))
        points['_Assert']='0x2000'
        self.assertEqual(bringup.checkpoint_guard_options('0x1000',points).count('0x2000'),1)
        self.assertEqual(bringup.checkpoint_guard_options('0x1000',{}),[])

    def test_boot_observers_decode_complete_reads_without_guessing_zero(self):
        observers={'_prng_ready':{'address':'0x1000','bytes':4},
                   '_rootvnode':{'address':'0x2000','bytes':8},
                   '_rootdev':{'address':'0x3000','bytes':4}}
        result=bringup.decode_boot_observers(observers,{'0x1000:0x4':'01000000',
                                                       '0x2000:0x8':'E14'})
        self.assertEqual(result['_prng_ready']['value'],1)
        for name in ('_rootvnode','_rootdev'):
            self.assertEqual(result[name]['status'],'unreadable or absent')
            self.assertNotIn('value',result[name])
        self.assertIn('_IOKitBSDInit',bringup.BOOT_TRACES)
        self.assertNotIn('_IOBSDInit',bringup.BOOT_TRACES)

    def test_stop_symbolization_uses_exact_range_and_captured_va_width(self):
        base=0xfffffff007004000
        image=SimpleNamespace(base=base,
            segments=[{'name':'__TEXT_EXEC','va':base+0x100,'filesize':0x200}],
            function_starts=lambda:[base+0x100,base+0x180],
            symbols=lambda:{base+0x100:['_first'],base+0x180:['_second']},
            read=lambda address,length:bytes(length))
        address=base+0x188
        signed=(address&((1<<38)-1)) | (0x12345<<38)
        result=bringup.symbolize_function(image,signed,38)
        self.assertEqual(result['address'],hex(address))
        self.assertEqual(result['names'],['_second'])
        self.assertEqual(result['offset'],8)
        self.assertEqual(result['function_sha256'],hashlib.sha256(bytes(0x180)).hexdigest())
        self.assertEqual(result['complete_function_bytes'],bytes(0x180).hex())
        outside=bringup.symbolize_function(image,base+0x800,38)
        self.assertEqual(outside['status'],'outside native executable ranges')
        with tempfile.TemporaryDirectory() as directory:
            payload=Path(directory)/'kernel.macho'
            payload.write_bytes(b'not the captured kernel')
            with self.assertRaisesRegex(ValueError,'different kernel image'):
                bringup.symbolize_stop(payload,Path(directory),{'kernel_sha256':'wrong'})

    @unittest.skipUnless((DEVICE.parents[1]/'references/pdx234-mainline-20261108/.git').is_dir(),
                         'local pinned mainline source required')
    def test_real_qemu_generator_supplies_required_ctrr_property(self):
        mainline=DEVICE.parents[1]/'references/pdx234-mainline-20261108'
        baseline=subprocess.check_output(['git','-C',str(mainline),'show',
                                         'HEAD:scripts/qemu-entry/make-dt.py'])
        patch_data=(DEVICE/'ci/qemu/no-ctrr.patch').read_bytes()
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            target=root/'scripts/qemu-entry/make-dt.py'
            target.parent.mkdir(parents=True)
            target.write_bytes(baseline)
            shutil.copytree(mainline/'scripts/unixnu',root/'scripts/unixnu',
                            ignore=shutil.ignore_patterns('__pycache__'))
            subprocess.run(['git','init','--quiet',str(root)],check=True)

            def chosen_properties(data):
                def read_node(at):
                    count,children=struct.unpack_from('<II',data,at)
                    at+=8
                    properties={}
                    for _ in range(count):
                        name=data[at:at+32].split(b'\0',1)[0].decode()
                        length=struct.unpack_from('<I',data,at+32)[0]&0x7fffffff
                        at+=36
                        properties[name]=data[at:at+length]
                        at+=(length+3)&~3
                    nodes=[]
                    for _ in range(children):
                        node,at=read_node(at)
                        nodes.append(node)
                    return (properties,nodes),at
                node,end=read_node(0)
                self.assertEqual(end,len(data))
                return next(props for props,_ in node[1] if props.get('name')==b'chosen\0')

            output=root/'test.adt'
            command=[sys.executable,str(target),'--armvirt','--armcpu',
                     '--qemu-vmm-present','--output',str(output)]
            subprocess.run(command,check=True,capture_output=True)
            self.assertNotIn('kernel-ctrr-to-be-enabled',chosen_properties(output.read_bytes()))
            prepare.apply_mainline_patch(root,patch_data)
            subprocess.run(command,check=True,capture_output=True)
            self.assertEqual(chosen_properties(output.read_bytes())['kernel-ctrr-to-be-enabled'],
                             struct.pack('<I',0))
            changed=target.read_bytes()
            with self.assertRaisesRegex(RuntimeError,'source patch failed'):
                prepare.apply_mainline_patch(root,patch_data)
            self.assertEqual(target.read_bytes(),changed)

    def test_qemu_overrides_do_not_change_device_arguments(self):
        base=['-v','serial=3','debug=0x14e']
        saved=list(base)
        line=bringup.merged_boot_arguments(base,['serial=1','interrupt-masked-debug-mode=1'])
        self.assertEqual(base,saved)
        self.assertEqual(line,'-v serial=1 debug=0x14e interrupt-masked-debug-mode=1')
        workflow=(DEVICE/'.github/workflows/package.yml').read_text()
        kernel=workflow.split('- name: Build kernel using official archive/prelink chain')[1] \
                       .split('- name: Verify completed RELEASE-LTO comparison')[0]
        self.assertNotIn('interrupt-masked-debug-mode',kernel)
        self.assertIn('--kernel-arg interrupt-masked-debug-mode=1',workflow)
        self.assertIn('--kernel-arg sched_preemption_disable_debug_mode=1',workflow)
        self.assertNotIn('sched_preemption_disable_debug_mode',kernel)
        import tomllib
        board=tomllib.loads((DEVICE/'board.toml').read_text())
        self.assertNotIn('interrupt-masked-debug-mode=1',board['payload']['kernel_args'])
        self.assertNotIn('sched_preemption_disable_debug_mode=1',board['payload']['kernel_args'])
        self.assertIn('_IOFindBSDRoot',bringup.CHECKPOINTS)
        self.assertEqual(bringup.BOOT_OBSERVERS['_source_corecrypto14_status'],4)
        self.assertEqual(bringup.BOOT_OBSERVERS['_rootvnode'],8)

    def test_qemu_overrides_reject_invalid_or_oversized_arguments(self):
        for value in ('arg=1;command','arg with spaces','arg='):
            with self.assertRaisesRegex(ValueError,'Unsupported'):
                bringup.merged_boot_arguments([], [value])
        with self.assertRaisesRegex(ValueError,'1000 bytes'):
            bringup.merged_boot_arguments([], ['arg='+'x'*1000])

    def test_lto_reference_is_built_once_after_dependencies(self):
        import tomllib
        board=tomllib.loads((DEVICE/'board.toml').read_text())
        archives=board['kernel']['archives']
        command='build-fileset-release-reference.py --tree . --lto'
        self.assertEqual(archives.count(command),1)
        self.assertEqual(archives[-1],command)
        workflow=(DEVICE/'.github/workflows/package.yml').read_text()
        self.assertIn('Verify completed RELEASE-LTO comparison',workflow)
        self.assertIn('verify-fileset-reference.py',workflow)
        self.assertNotIn('build-fileset-release-reference.py --tree',workflow)

    def test_reference_receipt_rejects_non_lto_and_changed_binary(self):
        with tempfile.TemporaryDirectory() as directory:
            tree=Path(directory)
            folder=tree/'build/xnu/fileset-reference'
            build=folder/'lto-test'
            build.mkdir(parents=True)
            binary=folder/'mach.release.bcm2837.unstripped.noctf'
            binary.write_bytes(b'reference fixture')
            command=['BUILD_LTO=1','KERNEL_CONFIGS=RELEASE',
                     'ARCH_STRING_FOR_CURRENT_MACHINE_CONFIG=arm64e']
            (build/'lto-command.json').write_text(json.dumps(command))
            record={'inputs':{'mode':'lto','compiler':'fixture','versions':{}},
                    'sha256':hashlib.sha256(binary.read_bytes()).hexdigest(),'build':str(build)}
            binary.with_suffix('.json').write_text(json.dumps(record))
            self.assertEqual(reference.verify(tree)['builds_started_by_check'],0)
            record['inputs']['mode']='snapshot'
            binary.with_suffix('.json').write_text(json.dumps(record))
            with self.assertRaisesRegex(ValueError,'not built with LTO'):
                reference.verify(tree)
            record['inputs']['mode']='lto'
            binary.with_suffix('.json').write_text(json.dumps(record))
            binary.write_bytes(b'changed')
            with self.assertRaisesRegex(ValueError,'completed-build receipt'):
                reference.verify(tree)

    def test_ci_fixture_preserves_reviewed_api_contracts(self):
        fixture=DEVICE/'ci/XnuPrelink/fixtures/fileset-24A446-d27-symbols.json'
        records=json.loads(fixture.read_text())['functions']
        functions={record['original']:record for record in records}
        self.assertEqual(len(functions),len(records))
        expected={'0xfffffff00aa362e4':'_SecureDTLookupEntry',
                  '0xfffffff00a1f3a90':'_lck_mtx_gate_close',
                  '0xfffffff00a1f395c':'_lck_mtx_gate_try_close',
                  '0xfffffff00a317f24':'___memcpy_chk',
                  '0xfffffff00a6ac950':'_csblob_get_auxiliary_info',
                  '0xfffffff00a724a88':'_set_compilation_service_cdhash_ext',
                  '0xfffffff00a724b08':'_match_compilation_service_cdhash_ext',
                  '0xfffffff00a3af664':'_vnode_lookup',
                  '0xfffffff00aa1c704':'_kernel_image4_storage_data',
                  '0xfffffff00a724360':'_garbage_collect_provisioning_profiles',
                  '0xfffffff00a6adca4':'_launch_constraint_data_get_launch_type',
                  '0xfffffff00a34f918':'_cpu_number',
                  '0xfffffff00a34f928':'_ml_get_wake_timebase',
                  '0xfffffff00a3beb2c':'_vnode_getfromfd',
                  '0xfffffff00a356bb8':'_ml_stack_remaining',
                  '0xfffffff00a21a938':'_smr_leave',
                  '0xfffffff00a6e6cec':'_proc_ppid',
                  '0xfffffff00a394cd4':'_cluster_max_io_size',
                  '0xfffffff00a1e5da0':'_zfree',
                  '0xfffffff00a25ae98':'_zfree',
                  '0xfffffff00a25badc':'_zone_require_ro',
                  '0xfffffff00a3e1a34':'_vnode_setmountedon',
                  '0xfffffff00a3eb150':'_cp_os_version',
                  '0xfffffff00a6e77a8':'_proc_name',
                  '0xfffffff00a3f84e4':'_decmpfs_cnode_free',
                  '0xfffffff00a234300':'_task_reference',
                  '0xfffffff00a1f22ac':'_lck_rw_gate_destroy',
                  '0xfffffff00a69c288':'_ktriage_record',
                  '0xfffffff00a90d2fc':'__ZN9IOService10makeUsableEv',
                  '0xfffffff00a6ad3f8':'_csfg_get_teamid',
                  '0xfffffff00a6e8680':'_proc_getexecutablevnode',
                  '0xfffffff00a724c9c':'_csm_resolve_os_entitlements_from_proc',
                  '0xfffffff00a213f38':'_sched_enable_acc_rail',
                  '0xfffffff00a214224':'_sched_disable_acc_rail',
                  '0xfffffff00a8b14ac':'__ZN9IOService12Start_InvokeE5IORPCP15OSMetaClassBasePFiS2_PS_E',
                  '0xfffffff00a8b15c8':'__ZN9IOService11Stop_InvokeE5IORPCP15OSMetaClassBasePFiS2_PS_E'}
        for address,symbol in expected.items():
            self.assertEqual(functions[address]['native_symbol'],symbol)
            self.assertEqual(functions[address]['verification'],'source-and-disassembly')
        manifest=json.loads((DEVICE/'ci/source-overlays.json').read_text())
        entry=next(e for e in manifest['component_files']
                   if e['path']=='fixtures/fileset-24A446-d27-symbols.json')
        self.assertEqual(prepare.digest(fixture.read_bytes()),entry['sha256_lf'])

    def test_reviewed_adapters_record_their_native_limits(self):
        records=json.loads((DEVICE/'ci/XnuPrelink/fixtures/fileset-24A446-d27-symbols.json').read_text())
        functions={record['original']:record for record in records['functions']}
        self.assertIn('other lengths are ignored',functions['0xfffffff00a724a88']['native_contract'])
        self.assertIn('other lengths return false',functions['0xfffffff00a724b08']['native_contract'])
        self.assertIn('static Image4 storage',functions['0xfffffff00aa1c704']['native_contract'])
        self.assertIn('performs no collection',functions['0xfffffff00a724360']['native_contract'])
        self.assertIn('C return type int',functions['0xfffffff00a34f918']['native_contract'])
        self.assertIn('requiring vnode_put',functions['0xfffffff00a3beb2c']['native_contract'])
        self.assertIn('remaining space',functions['0xfffffff00a356bb8']['native_contract'])
        self.assertIn('SMR_SEQ_INVALID',functions['0xfffffff00a21a938']['native_contract'])
        self.assertIn('native PAGE_SIZE',functions['0xfffffff00a394cd4']['native_contract'])
        for address in ('0xfffffff00a1e5da0','0xfffffff00a25ae98'):
            self.assertIn('not uniquely disambiguated',functions[address]['identity_scope'])
        self.assertIn('ASCII character',functions['0xfffffff00a3eb150']['native_contract'])
        self.assertIn('separate destroy API',functions['0xfffffff00a3f84e4']['native_contract'])
        self.assertIn('not uniquely disambiguated',functions['0xfffffff00a1f22ac']['identity_scope'])
        self.assertIn('do not free',functions['0xfffffff00a1f22ac']['native_contract'])
        self.assertIn('three-scalar ABI',functions['0xfffffff00a69c288']['evidence'])
        self.assertIn('borrowed',functions['0xfffffff00a6ad3f8']['native_contract'])
        self.assertIn('requiring vnode_put',functions['0xfffffff00a6e8680']['native_contract'])
        self.assertIn('KERN_NOT_SUPPORTED(46)',functions['0xfffffff00a724c9c']['native_contract'])
        self.assertIn('synchronously',functions['0xfffffff00a213f38']['native_contract'])
        self.assertIn('asynchronously',functions['0xfffffff00a214224']['native_contract'])
        self.assertIn('0xab6f76dde6d693f2',functions['0xfffffff00a8b14ac']['evidence'])
        self.assertIn('0x98e715041c459fa5',functions['0xfffffff00a8b15c8']['evidence'])

    def test_parent_match_key_is_a_native_initialized_global_slot(self):
        record=json.loads((DEVICE/'ci/XnuPrelink/fixtures/fileset-24A446-d27-symbols.json').read_text())
        keys=[entry for entry in record['data'] if entry['original']=='0xfffffff00ad56940']
        self.assertEqual(len(keys),1)
        self.assertEqual(keys[0]['native_symbol'],'_gIOParentMatchKey')
        self.assertEqual(keys[0]['original_section'],'__DATA,__common')
        self.assertEqual(keys[0]['original_initializer'],'0xfffffff00a8ed8b0')
        self.assertIn('not file-backed',keys[0]['evidence'])

    def test_custom_phone_profile_is_staged_before_configuration(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            device=root/'device'
            profile=device/'profiles/iphone14-test'
            (profile/'configs').mkdir(parents=True)
            (device/'board.toml').write_text('[board]\nos_profile="iphone14-test"\n')
            (profile/'profile.toml').write_text('[ipsw]\nproduct="iPhone14,7"\n')
            (profile/'configs/ios.config').write_text('CONFIG_TEST=y\n')
            files=prepare.stage_profile(device,root/'UniXNU')
            self.assertEqual(set(files),{'profile.toml','configs/ios.config'})
            copied=root/'UniXNU/profiles/os/iphone14-test/profile.toml'
            self.assertEqual(copied.read_bytes(),(profile/'profile.toml').read_bytes())
            with self.assertRaisesRegex(RuntimeError,'Refuse to replace'):
                prepare.stage_profile(device,root/'UniXNU')

    def test_log_redaction_removes_tokens_and_signed_urls(self):
        with patch.dict(os.environ,{'GITHUB_TOKEN':'test-secret','UNIXNU_UNIQUE_CHIP_ID':'11223344'}):
            text=collector.redact('test-secret 11223344 https://example.test/input?token=private')
        self.assertNotIn('test-secret',text)
        self.assertNotIn('11223344',text)
        self.assertNotIn('private',text)

    def test_collects_strict_failure_report_from_work_tree(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            work=root/'work'
            (work/'kernel').mkdir(parents=True)
            (work/'kernel/kernel.failed.json').write_text('{"unresolved":[{"target":4096}]}')
            (work/'.prelink-old/staging').mkdir(parents=True)
            (work/'.prelink-old/staging/kernel.json').write_text('{"unresolved":[]}')
            destination=root/'dest'
            (root/'mainline').mkdir()
            with patch.object(collector,'selected_work',return_value=work), \
                    patch.object(sys,'argv',['collect-macos-logs.py','--mainline',
                                             str(root/'mainline'),'--destination',str(destination)]):
                collector.main()
            names=sorted(path.name for path in destination.glob('*.log'))
            self.assertTrue(any(name.endswith('kernel.failed.json.log') for name in names),names)
            self.assertTrue(any(name.endswith('kernel.json.log') for name in names),names)

    def test_workflow_tracks_current_sheng_main_pin(self):
        workflow=(DEVICE/'.github/workflows/package.yml').read_text()
        vendored=(DEVICE/'ci/reference/sheng-main-package.yml').read_text()
        pin='82b847c4ac3f68a57024b3082ffa3a03442defd9'
        self.assertIn('ref: '+pin,workflow)
        self.assertEqual(prepare.reference_pin(vendored),pin)
        self.assertIn('submodules: recursive',workflow)
        self.assertNotIn('689400177f93219a38bd7cf5ae2e9f5782adc594',workflow)
        self.assertNotIn('reference-sheng',workflow)
        self.assertIn('rustup toolchain install 1.98.0',workflow)
        self.assertIn('--component rust-src',workflow)
        brew=[line.strip() for line in workflow.splitlines() if line.strip().startswith('brew install')]
        self.assertEqual(brew,['brew install dtc llvm lld cmake mtools ninja bison pkgconf rustup qemu'])
        for tool in ('fdtget','fdtput','aea','compression_tool','llvm-nm','llvm-objcopy','lld-link','llvm-lib','llvm-rc'):
            self.assertIn(tool,workflow)

    def test_arch_patch_anchor_failure_names_the_series(self):
        with tempfile.TemporaryDirectory() as directory:
            mainline=Path(directory)
            arch=mainline/'profiles/arch/arm64e/patches/xnu'
            arch.mkdir(parents=True)
            (arch/'series').write_text('one.patch\ntwo.patch\n')
            with self.assertRaisesRegex(RuntimeError,'audited arm64e series'):
                prepare.insert_arch_patch(mainline,'native-metaclass-vptr-poison.patch',b'patch\n')
            self.assertFalse((arch/'native-metaclass-vptr-poison.patch').exists())

    def test_prepare_macos_rejects_a_different_vendor_pin(self):
        vendored=(DEVICE/'ci/reference/sheng-main-package.yml').read_text()
        self.assertEqual(prepare.reference_pin(vendored),'82b847c4ac3f68a57024b3082ffa3a03442defd9')
        with self.assertRaisesRegex(RuntimeError,'does not pin'):
            prepare.reference_pin('name: package\n')

    def test_experimental_emission_is_a_separate_allow_missing_step(self):
        workflow=(DEVICE/'.github/workflows/package.yml').read_text()
        strict=workflow.split('- name: Build kernel using official archive/prelink chain')[1] \
                       .split('- name: Emit experimental allow-missing candidate')[0]
        self.assertNotIn('--allow-missing',strict)
        self.assertIn("if: failure() && steps.kernel.outcome == 'failure'",workflow)
        self.assertIn('qemu-bringup.py" emit',workflow)
        self.assertIn('qemu-bringup.py" boot',workflow)
        self.assertIn('allow_missing',(DEVICE/'scripts/ci/qemu-bringup.py').read_text())
        self.assertIn("${{ runner.temp }}/public-logs/*.json",workflow)
        self.assertIn("${{ runner.temp }}/public-logs/*.png",workflow)
        self.assertNotIn('public-logs/*.macho',workflow)
        self.assertNotIn('public-logs/*.efi',workflow)
        self.assertIn('if-no-files-found: warn',workflow)

    def test_emit_command_keeps_strict_default_and_can_allow_missing(self):
        spec={'tool':'kits/XnuPrelink/emit_prelink.py','kernel':'build/native',
              'slide':'0','roots':['com.apple.kern','com.apple.kpi'],
              'early_security_init':'com.apple.driver.AppleMobileFileIntegrity=0xfffffff008e8fe7c',
              'extra_args':['--fileset-reference','build/reference']}
        strict=bringup.emit_command(spec,Path('/cache'),Path('/out/kernel.macho'),allow_missing=False)
        self.assertNotIn('--allow-missing',strict)
        self.assertEqual(strict.count('--root'),2)
        self.assertIn('com.apple.driver.AppleMobileFileIntegrity=0xfffffff008e8fe7c',strict)
        self.assertIn('--fileset-reference',strict)
        experimental=bringup.emit_command(spec,Path('/cache'),Path('/out/kernel.macho'))
        self.assertEqual(experimental[-3:],['--allow-missing','--output','/out/kernel.macho'])

    def test_unresolved_counts_match_the_report_tables(self):
        report={'missing':{'com.apple.kern':{'0x1':1,'0x2':2},'com.apple.kpi':{'0x1':1}},
                'stubbed':{'com.apple.kern':{'0x9':1}}}
        counts=bringup.unresolved(report)
        self.assertEqual(counts['references'],5)
        self.assertEqual(counts['unique_targets'],3)
        self.assertEqual(counts['bundles'],2)
        self.assertEqual(counts['stubbed_references'],1)

    def test_workflow_preserves_kernel_only_delivery_guard(self):
        workflow=(DEVICE/'.github/workflows/package.yml').read_text()
        self.assertIn('runs-on: macos-26',workflow)
        self.assertIn('./unixnu build kernel',workflow)
        self.assertIn('kit:XnuPrelink=',workflow)
        self.assertNotIn('scripts/package.sh "',workflow)
        self.assertNotIn('uefi-sheng',workflow)
        self.assertNotIn('data.dbr',workflow)
        self.assertIn('/public-logs/*.log',workflow)


if __name__=='__main__':unittest.main()
