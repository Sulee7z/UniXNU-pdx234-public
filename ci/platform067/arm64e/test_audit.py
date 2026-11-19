#!/usr/bin/env python3
"""Unit tests for conservative patch parsing and the exact isolated upstream hunk."""
import unittest

from audit import Hunk, parse_patch, locate, changed_chunks, Replay
from addon_size_overlay import adapt, ANCHOR, ADDITION


class PatchTests(unittest.TestCase):
    def test_simple_hunk(self):
        text = '--- a/a.c\n+++ b/a.c\n@@ -1,2 +1,3 @@ f\n a\n+b\n c\n'
        diff = parse_patch(text)[0]
        self.assertEqual(diff.path, 'a.c')
        self.assertEqual(diff.hunks[0].old(), ['a', 'c'])
        self.assertEqual(diff.hunks[0].new(), ['a', 'b', 'c'])

    def test_timestamps_and_new_file(self):
        text = '--- /dev/null\t2026-11-18\n+++ b/new.h\t2026-11-18\n@@ -0,0 +1 @@\n+x\n'
        diff = parse_patch(text)[0]
        self.assertTrue(diff.created)
        self.assertEqual(diff.path, 'new.h')

    def test_choose_nearest_exact_match(self):
        self.assertEqual(locate(['a', 'b', 'a', 'b'], ['a', 'b'], 2), 2)
        self.assertIsNone(locate(['a'], ['absent'], 0))

    def test_no_patch_is_error(self):
        with self.assertRaises(ValueError):
            parse_patch('not a diff')

    def test_addition_chunks_do_not_require_unchanged_context(self):
        hunk = Hunk(1, 1, [('+', 'one'), (' ', 'middle'), ('+', 'two')], '')
        self.assertEqual(changed_chunks(hunk), [['one'], ['two']])

    def test_ordered_replay_keeps_last_writer(self):
        replay = Replay(None)
        replay.files['a.c'] = [('begin', None), ('old', None), ('end', None)]
        replay.apply('first', parse_patch('--- a/a.c\n+++ b/a.c\n@@ -1,3 +1,3 @@\n begin\n-old\n+new\n end\n'))
        replay.apply('later', parse_patch('--- a/a.c\n+++ b/a.c\n@@ -1,3 +1,3 @@\n begin\n-new\n+final\n end\n'))
        self.assertEqual(replay.files['a.c'], [('begin', None), ('final', 'later'), ('end', None)])
        self.assertEqual(replay.errors, [])

    def test_replay_cannot_fuzz_insert_after_unrelated_else(self):
        replay = Replay(None)
        replay.files['a.c'] = [('#else', None), ('unrelated();', None), ('#endif', None), ('', None)]
        replay.apply('test', parse_patch('--- a/a.c\n+++ b/a.c\n@@ -1,4 +1,5 @@\n #else\n expected();\n #endif\n+record();\n \n'))
        self.assertEqual(len(replay.errors), 1)
        self.assertNotIn(('record();', 'test'), replay.files['a.c'])


class OverlayTests(unittest.TestCase):
    def fixture(self):
        source = 'static int\nnative_gpu_addon_write(void)\n{\n' + ANCHOR + '\n}\n'
        official = '--- a/f.c\n+++ b/f.c\n@@ -1 +1,3 @@\n x\n' + ''.join('+' + line + '\n' for line in ADDITION.splitlines())
        return source, official

    def test_only_two_official_lines_added(self):
        source, official = self.fixture()
        result = adapt(source, official)
        self.assertEqual(result.replace(ADDITION, ''), source)
        self.assertEqual(result.count('VATTR_SET(&va, va_data_size, size);'), 1)

    def test_reject_already_patched(self):
        source, official = self.fixture()
        with self.assertRaises(ValueError):
            adapt(adapt(source, official), official)

    def test_reject_ambiguous_anchor(self):
        source, official = self.fixture()
        with self.assertRaises(ValueError):
            adapt(source + source, official)

    def test_reject_wrong_function(self):
        source, official = self.fixture()
        with self.assertRaises(ValueError):
            adapt(source.replace('native_gpu_addon_write', 'unrelated_write'), official)

    def test_reject_nonofficial_hunk(self):
        source, official = self.fixture()
        with self.assertRaises(ValueError):
            adapt(source, official.replace('va_data_size', 'other_field'))


if __name__ == '__main__':
    unittest.main()
