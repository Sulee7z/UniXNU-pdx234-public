#!/usr/bin/env python3
import importlib.util
import json
from pathlib import Path
import struct
import unittest


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('radio_adt069', ROOT / 'ci/platform069/radio_adt.py')
radio_adt = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(radio_adt)


class SonyRadioAdt069Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        radio_adt.verify_inputs()
        cls.original = radio_adt.BASE_ADT.read_bytes()
        cls.original_tree = radio_adt.parse_adt(cls.original)
        cls.result, cls.delta = radio_adt.overlay_adt(cls.original)
        cls.tree = radio_adt.parse_adt(cls.result)

    def test_frozen_068_baseline_is_source_pinned(self):
        self.assertEqual(radio_adt.sha256(self.original), radio_adt.BASE_ADT_SHA256)
        self.assertEqual(radio_adt.sha256(radio_adt.LIVE_DTB.read_bytes()), radio_adt.LIVE_DTB_SHA256)
        self.assertEqual(set(radio_adt.verify_inputs()['source_pins']), set(radio_adt.PINS))

    def test_live_sony_nodes_are_hash_bound(self):
        nodes = radio_adt.live_fdt().nodes
        board = json.loads(radio_adt.BOARD_INPUTS.read_text())
        self.assertIn('qcom,wlan', nodes[board['wifi_node']])
        self.assertEqual(nodes[board['wifi_node']]['supported-ids'], struct.pack('>I', 0x1107))
        self.assertEqual(nodes[board['bluetooth_node']]['compatible'], b'qcom,kiwi\0')

    def test_original_d27_wifid_condition_is_verified_without_editing_it(self):
        original = radio_adt.verify_inputs()['original_wifid']
        self.assertIn('wlan', original['_LimitLoadToDeviceTree'])
        self.assertEqual(original['launchd_plist_sha256'], radio_adt.D27_LAUNCHD_SHA256)

    def test_captured_nvm_addresses_are_shared_defaults_not_unit_identity(self):
        provenance = radio_adt.audit_addresses(radio_adt.live_fdt())
        self.assertEqual(provenance['hamilton_nvm_shared_default']['verified_variants'], 47)
        self.assertFalse(provenance['hamilton_nvm_shared_default']['used_as_sony_bd_addr'])
        sample = (radio_adt.CAPTURE / 'bluetooth-firmware/hmtnv20.bin').read_bytes()
        self.assertEqual(radio_adt.decode_hamilton_nvm_address(sample), (0x5c, b'\xad\x5a\0\0\0\0'))
        for damaged in (b'', sample[:-1], b'\x01' + sample[1:]):
            with self.subTest(damaged_bytes=len(damaged)), self.assertRaises(ValueError):
                radio_adt.decode_hamilton_nvm_address(damaged)

    def test_encoding_matches_the_pinned_official_generator(self):
        import ast
        filename = radio_adt.UNIXNU_REPO / 'scripts/unixnu/devicetree.py'
        syntax = ast.parse(filename.read_text())
        node_function = next(node for node in syntax.body if isinstance(node, ast.FunctionDef) and node.name == 'node')
        namespace = {'struct': struct, 'Error': ValueError}
        exec(compile(ast.Module(body=[node_function], type_ignores=[]), str(filename), 'exec'), namespace)
        for name, encoded in radio_adt.expected_nodes().items():
            props = radio_adt._scan_node(encoded)[0]['properties']
            self.assertEqual(namespace['node'](name, [(key, value) for key, value in props.items() if key != 'name']), encoded)

    def test_source_overlay_is_local_to_actual_wifi_entry(self):
        spec = importlib.util.spec_from_file_location('address_overlay069', ROOT / 'ci/platform069/radio_address.py')
        adapter = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(adapter)
        source = (radio_adt.ARTIFACTS / 'radio-provider069-007/source/WifiProbe.cpp').read_text()
        adapted = adapter.wifi(source)
        self.assertEqual(adapter.validate_bodies(source), adapter.validate_bodies(adapted))
        declaration = 'extern "C" int native_sony_wifi_publish(void);\n'
        insertion = ('    const int addressError069=native_sony_wifi_publish();\n'
                     '    if(addressError069){native_wifi_stats[0]=(uint32_t)-addressError069;return;}\n')
        self.assertTrue(adapted.startswith(declaration))
        self.assertEqual(adapted.count(insertion), 1)
        self.assertEqual(adapted[len(declaration):].replace(insertion, '', 1), source)
        entry = adapter.function(adapted, 'extern "C" void native_sony_wifi_start(void)')
        order = ['sony_wcn_platform_ready()', 'sony_wcn_platform_wifi_ready()', 'if(ready)',
                 'native_sony_wifi_publish();', 'kernel_thread_start(']
        offsets = [entry.index(anchor) for anchor in order]
        self.assertEqual(offsets, sorted(offsets))
        self.assertNotIn('sony_wcn_wifi_inputs_ready', entry)
        worker = adapter.function(adapted, 'void wifiThread(void *arg, wait_result_t)')
        self.assertLess(worker.index('sony_wcn_wifi_inputs_ready'), worker.index('publishMac();'))
        self.assertLess(worker.index('sony_wcn_wifi_inputs_ready'), worker.index('mapWindow('))
        self.assertLess(worker.index('sony_wcn_wifi_inputs_ready'), worker.index('bringUp('))
        self.assertIn('for(unsigned i=0;i<240 && ready==EAGAIN;++i)', worker)
        with self.assertRaises(ValueError):
            adapter.wifi(adapted)
        with self.assertRaises(ValueError):
            adapter.wifi(source.replace('hash', 'unexpected', 1).replace('bool boardMac(', 'bool differentMac(', 1))

    def test_exact_main_adapt_then_radio_address_composition_matches_provider007(self):
        adapter = radio_adt.load_module('address_overlay_compose069', ROOT / 'ci/platform069/radio_address.py')
        main = radio_adt.load_module('main_wifi_compose069', ROOT / 'drivers/SonyWcn/platform069/adapt069.py')
        original = Path('/mnt/e/UniXNU-sheng27-sony-20261113/sony-wcn-067-002/source/WifiProbe.cpp').read_text()
        expected = (radio_adt.ARTIFACTS / 'radio-provider069-007/source/WifiProbe.cpp').read_text()
        adapted = main.wifi(original)
        self.assertTrue(adapted == expected, 'Current adapt069.wifi must reproduce the frozen build007 source')
        self.assertEqual(adapter.wifi(adapted), adapter.wifi(expected))
        official = (radio_adt.SHENG_REPO / 'package/WifiProbe.cpp').read_text()
        self.assertEqual(adapter.validate_bodies(adapter.wifi(adapted)), adapter.validate_bodies(official))

    def test_adds_actual_apple_consumer_paths_with_source_abi(self):
        self.assertEqual(radio_adt.at_path(self.tree, '/device-tree/arm-io/wlan')['properties']['compatible'],
                         b'qcom,wcn7850\0')
        bt = radio_adt.at_path(self.tree, '/device-tree/arm-io/bluetooth')['properties']
        self.assertEqual(bt['device_type'], b'bluetooth\0')
        self.assertEqual(bt['compatible'], b'qcom,wcn7850-bt\0')
        self.assertEqual(bt['transport-encoding'], struct.pack('<I', 1))
        self.assertEqual(bt['transport-speed'], struct.pack('<I', 3_200_000))

    def test_identity_and_original_tree_semantics_are_unchanged(self):
        old_chosen = radio_adt.at_path(self.original_tree, '/device-tree/chosen')['properties']
        new_chosen = radio_adt.at_path(self.tree, '/device-tree/chosen')['properties']
        self.assertEqual(new_chosen, old_chosen)
        for path in ('/device-tree', '/device-tree/cpus', '/device-tree/arm-io/intc',
                     '/device-tree/defaults', '/device-tree/options', '/device-tree/product'):
            with self.subTest(path=path):
                old = radio_adt.at_path(self.original_tree, path)
                new = radio_adt.at_path(self.tree, path)
                self.assertEqual(new['properties'], old['properties'])
                if path != '/device-tree/arm-io':
                    self.assertEqual([c['name'] for c in new['children']], [c['name'] for c in old['children']])

    def test_only_arm_io_child_count_and_two_new_nodes_change_wire_bytes(self):
        field = self.delta['child_count_field_offset']
        insert = self.delta['insert_offset']
        inserted = self.delta['inserted_bytes']
        self.assertEqual(self.result[:field], self.original[:field])
        self.assertEqual(self.result[field + 4:insert], self.original[field + 4:insert])
        self.assertEqual(self.result[insert:insert + inserted],
                         b''.join(radio_adt.expected_nodes().values()))
        self.assertEqual(self.result[insert + inserted:], self.original[insert:])
        self.assertEqual(self.delta['added'], ['wlan', 'bluetooth'])

    def test_independent_original_parser_accepts_the_new_bytes(self):
        spec = importlib.util.spec_from_file_location('independent_adt069', ROOT / 'scripts/apple-device-tree.py')
        codec = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(codec)
        original, changed = codec.parse(self.original), codec.parse(self.result)
        radio_children = changed['children']['arm-io']['children']
        self.assertEqual(set(radio_children), {'intc', 'wlan', 'bluetooth'})
        del radio_children['wlan']
        del radio_children['bluetooth']
        self.assertEqual(original, changed)

    def test_overlay_is_idempotent(self):
        repeated, delta = radio_adt.overlay_adt(self.result)
        self.assertEqual(repeated, self.result)
        self.assertTrue(delta['idempotent'])
        self.assertEqual(delta['added'], [])

    def test_no_physical_mac_is_invented(self):
        chosen = radio_adt.at_path(self.tree, '/device-tree/chosen')['properties']
        wlan = radio_adt.at_path(self.tree, '/device-tree/arm-io/wlan')['properties']
        bt = radio_adt.at_path(self.tree, '/device-tree/arm-io/bluetooth')['properties']
        self.assertNotIn('mac-address-wifi0', chosen)
        self.assertNotIn('mac-address-bluetooth0', chosen)
        self.assertNotIn('local-mac-address', wlan)
        self.assertNotIn('local-mac-address', bt)
        self.assertIn('unique-chip-id', chosen)

    def test_existing_conflicting_node_is_rejected(self):
        # Reuse a generated node but give it an incompatible property; do not
        # silently overwrite a property supplied by a different ADT owner.
        original_arm = radio_adt.at_path(self.original_tree, '/device-tree/arm-io')
        conflicting = radio_adt._encode_node('wlan', [('compatible', b'qcom,other-radio\0')])
        arm_end = original_arm['end']
        damaged = bytearray(self.original[:arm_end] + conflicting + self.original[arm_end:])
        struct.pack_into('<I', damaged, original_arm['child_count_offset'], len(original_arm['children']) + 1)
        with self.assertRaisesRegex(ValueError, 'conflicts with selected source ABI'):
            radio_adt.overlay_adt(bytes(damaged))


if __name__ == '__main__':
    unittest.main()
