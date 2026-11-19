"""Execute the backported no-monitor/handler branches with host test doubles.

These test the source branches, not guest execution, TXM or Mach IPC. Actual
arm64e code generation and message layout are checked separately.
"""
import json
import importlib.util
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

DEVICE = Path(__file__).resolve().parents[1]
PATCH = DEVICE / 'patches/xnu/ios27-strict5-native-kpi.patch'
SYMBOL = '__ZN9IOService20CallPlatformFunctionEP8OSStringbP12OSDictionaryPS3_PFiP15OSMetaClassBase5IORPCE'


def additions(member):
    section = PATCH.read_text().split(f'diff --git a/{member} b/{member}\n', 1)[1]
    section = section.split('\ndiff --git ', 1)[0]
    return '\n'.join(line[1:] for line in section.splitlines()
                     if line.startswith('+') and not line.startswith('+++')) + '\n'


class Strict5Tests(unittest.TestCase):
    def test_identity_recovery_accepts_only_additive_evidence(self):
        spec = importlib.util.spec_from_file_location('strict5_importer', DEVICE / 'scripts/ci/import-runner-identities.py')
        importer = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(importer)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            old, new = root / 'old', root / 'new'
            fixture = {'inputs': {'kernelcache_sha256': 'pin', 'entry': 'com.apple.kernel'},
                       'functions': [{'original': '0x1000', 'native_symbol': '_one', 'evidence': 'proof'}]}
            for kit in (old, new):
                (kit / 'fixtures').mkdir(parents=True)
                for name in ('fileset_match.py', 'kc_image.py', 'fileset_shape.py'):
                    (kit / name).write_text('matching rules\n')
                (kit / 'fixtures/fileset-pin-symbols.json').write_text(json.dumps(fixture))
            first = importer.additive_reviewed_snapshot(old, new)
            fixture['functions'].append({'original': '0x1004', 'native_symbol': '_two', 'evidence': 'new proof'})
            path = new / 'fixtures/fileset-pin-symbols.json'
            path.write_text(json.dumps(fixture))
            self.assertEqual(importer.additive_reviewed_snapshot(old, new), first)
            fixture['functions'][0]['native_symbol'] = '_wrong'
            path.write_text(json.dumps(fixture))
            with self.assertRaisesRegex(ValueError, 'evidence changed'):
                importer.additive_reviewed_snapshot(old, new)
            (new / 'fileset_match.py').write_text('weakened matching rules\n')
            with self.assertRaisesRegex(ValueError, 'matching rules changed'):
                importer.additive_reviewed_snapshot(old, new)

    def compile_and_run(self, directory, source, language='c', extra=(), run=True):
        compiler = shutil.which('cc' if language == 'c' else 'c++')
        if compiler is None:
            self.skipTest('Host compiler unavailable')
        path = directory / ('test.c' if language == 'c' else 'test.cpp')
        path.write_text(source)
        output = directory / 'test'
        result = subprocess.run([compiler, '-Wall', '-Wextra', '-Werror', '-I', str(directory),
                                 *extra, str(path), '-o', str(output)], cwd=directory,
                                text=True, capture_output=True)
        if run:
            self.assertEqual(result.returncode, 0, result.stderr)
            result = subprocess.run([str(output)], cwd=directory, text=True, capture_output=True)
            self.assertEqual(result.returncode, 0, result.stderr)
        return result

    def test_fixture_exports_and_series(self):
        fixture = json.loads((DEVICE / 'ci/XnuPrelink/fixtures/fileset-24A446-d27-symbols.json').read_text())
        by_address = {row['original']: row for row in fixture['functions']}
        expected = {
            '0xfffffff00a72545c': '_image4_v2_set_nonce_digest',
            '0xfffffff00a7254d4': '_image4_v2_roll_nonce',
            '0xfffffff00a725540': '_image4_v2_load_diavlo_root_ca',
            '0xfffffff00a725560': '_image4_v2_load_local_policy',
            '0xfffffff00a8b485c': SYMBOL,
        }
        for address, symbol in expected.items():
            row = by_address[address]
            self.assertEqual(row['native_symbol'], symbol)
            self.assertEqual(row['verification'], 'source-and-disassembly')
            self.assertEqual(len(row['original_sha256']), 64)
            self.assertIn('evidence/d27-strict5-native-kpi.json', row['evidence'])
            if symbol != SYMBOL:
                self.assertIn('ENOTSUP', row['native_contract'])
            self.assertIn('+' + symbol, PATCH.read_text())
        self.assertIn(PATCH.name, (DEVICE / 'patches/xnu/series').read_text())

    def test_image4_no_monitor_and_invalid_inputs(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            headers = {
                'libkern/libkern.h': '#include <stdint.h>\n#include <stddef.h>\n#include <stdio.h>\ntypedef int errno_t;\n',
                'libkern/section_keywords.h': '', 'mach/mach_types.h': '',
                'sys/code_signing_internal.h': '#ifndef CODE_SIGNING_MONITOR\n#define CODE_SIGNING_MONITOR 0\n#endif\n',
                'sys/errno.h': '#define ENOTSUP 45\n',
            }
            for path, contents in headers.items():
                target = root / path
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_text(contents)
            source = '#include <libkern/libkern.h>\n' + additions('libkern/image4/image4_v2.c') + r'''
#include <assert.h>
int main(void) {
    const unsigned char data[4] = {1,2,3,4};
    assert(image4_v2_set_nonce_digest(1, data, 4) == ENOTSUP);
    assert(image4_v2_set_nonce_digest(UINT32_MAX, NULL, 0) == ENOTSUP);
    assert(image4_v2_roll_nonce(1) == ENOTSUP);
    assert(image4_v2_roll_nonce(UINT32_MAX) == ENOTSUP);
    assert(image4_v2_load_diavlo_root_ca(data,4,data,4) == ENOTSUP);
    assert(image4_v2_load_diavlo_root_ca(NULL,4,data,4) == 3);
    assert(image4_v2_load_diavlo_root_ca(data,0,data,4) == 3);
    assert(image4_v2_load_diavlo_root_ca(data,4,NULL,4) == 3);
    assert(image4_v2_load_diavlo_root_ca(data,4,data,0) == 3);
    assert(image4_v2_load_local_policy(data,4) == ENOTSUP);
    assert(image4_v2_load_local_policy(NULL,4) == 3);
    assert(image4_v2_load_local_policy(data,0) == 3);
    assert(data[0] == 1 && data[3] == 4);
    return 0;
}
'''
            self.compile_and_run(root, source)
            refused = self.compile_and_run(root, source, extra=('-DCODE_SIGNING_MONITOR=1',), run=False)
            self.assertNotEqual(refused.returncode, 0)
            self.assertIn('requires the no-monitor configuration', refused.stderr)

    def test_platform_dictionary_handler_and_ownership(self):
        prefix = r'''
#include <cassert>
#include <cstddef>
#include <cstdint>
#include <cstring>
using IOReturn = int;
using kern_return_t = int;
enum { kIOReturnSuccess=0, kIOReturnBadArgument=1, kIOReturnUnsupported=2, kIOReturnNoMemory=3 };
struct Task { bool driver; };
using task_t = Task*;
static task_t active;
static task_t current_task() { return active; }
static bool task_is_driver(task_t task) { return task->driver; }
struct OSString { const char* text; };
struct OSDictionary { int value; };
struct OSSymbol {
    const char* text;
    static int outstanding;
    static bool failQuery, failName;
    static const OSSymbol* withCStringNoCopy(const char* name) {
        if (failQuery) return nullptr;
        ++outstanding; return new OSSymbol{name};
    }
    static const OSSymbol* withString(OSString* name) {
        if (failName) return nullptr;
        ++outstanding; return new OSSymbol{name->text};
    }
    void release() const { --outstanding; delete this; }
};
int OSSymbol::outstanding=0;
bool OSSymbol::failQuery=false, OSSymbol::failName=false;
struct IOUserServer { task_t fOwningTask; };
struct UVars { IOUserServer* userServer; };
struct Reserved { UVars* uvars; };
struct IOService;
using Handler = IOReturn(*)(IOService*,const OSSymbol*,bool,OSDictionary*,OSDictionary**);
static Handler registered;
static IOReturn queryResult=kIOReturnSuccess, handlerResult=0;
static int queries=0, calls=0, forwards=0, logs=0;
static OSDictionary resultObject{42};
static IOReturn rawFunction(IOService*,const OSSymbol*,bool,OSDictionary*,OSDictionary**) { return 99; }
static Handler raw_handler=rawFunction;
#define OSMemberFunctionCast(Type,object,member) ((void)(member), raw_handler)
static void IOLog(const char*,const char*,unsigned long long) { ++logs; }
struct IOService {
    Reserved* reserved=nullptr;
    kern_return_t CallPlatformFunction_Impl(OSString*,bool,OSDictionary*,OSDictionary**);
    kern_return_t CallPlatformFunction(OSString*,bool,OSDictionary*,OSDictionary** out,void* supermethod) {
        assert(!supermethod); ++forwards; *out=&resultObject; return 66;
    }
    IOReturn callPlatformFunction(const OSSymbol* key,bool wait,void* out,void* a,void* b,void* c) {
        assert(!std::strcmp(key->text,"IOUserPlatformFunction"));
        assert(wait && out && !a && !b && !c); ++queries;
        *static_cast<Handler*>(out)=registered; return queryResult;
    }
    const char* getName() { return "test"; }
    unsigned long long getRegistryEntryID() { return 1; }
};
static IOReturn goodHandler(IOService*,const OSSymbol* name,bool wait,OSDictionary* input,OSDictionary** out) {
    assert(!std::strcmp(name->text,"callAppleARMFunction"));
    assert(wait && input->value==7); ++calls; *out=&resultObject; return handlerResult;
}
'''
        suffix = r'''
int main() {
    Task kernel{false}, driver{true}, other{true}; active=&kernel;
    IOService service; OSString name{"callAppleARMFunction"}; OSDictionary input{7};
    OSDictionary* out=&resultObject;
    assert(service.CallPlatformFunction_Impl(nullptr,true,&input,&out)==kIOReturnBadArgument);
    assert(service.CallPlatformFunction_Impl(&name,true,&input,nullptr)==kIOReturnBadArgument);
    assert(service.CallPlatformFunction_Impl(&name,true,&input,&out)==kIOReturnUnsupported);
    assert(!out && !queries && !calls && !forwards);
    active=&driver; registered=goodHandler;
    IOUserServer server{&other}; UVars uvars{&server}; Reserved reserved{&uvars}; service.reserved=&reserved;
    assert(service.CallPlatformFunction_Impl(&name,true,&input,&out)==66);
    assert(out==&resultObject && forwards==1 && !queries);
    server.fOwningTask=&driver;
    assert(service.CallPlatformFunction_Impl(&name,true,&input,&out)==0);
    assert(out==&resultObject && calls==1 && OSSymbol::outstanding==0);
    handlerResult=17;
    assert(service.CallPlatformFunction_Impl(&name,true,&input,&out)==17);
    assert(calls==2 && OSSymbol::outstanding==0);
    registered=rawFunction;
    assert(service.CallPlatformFunction_Impl(&name,true,&input,&out)==kIOReturnUnsupported);
    assert(logs==1 && calls==2 && !out);
    registered=nullptr;
    assert(service.CallPlatformFunction_Impl(&name,true,&input,&out)==kIOReturnUnsupported);
    registered=goodHandler; queryResult=17;
    assert(service.CallPlatformFunction_Impl(&name,true,&input,&out)==kIOReturnUnsupported);
    queryResult=0; OSSymbol::failQuery=true;
    assert(service.CallPlatformFunction_Impl(&name,true,&input,&out)==kIOReturnNoMemory);
    OSSymbol::failQuery=false; OSSymbol::failName=true;
    assert(service.CallPlatformFunction_Impl(&name,true,&input,&out)==kIOReturnNoMemory);
    assert(!out && OSSymbol::outstanding==0);
    return 0;
}
'''
        with tempfile.TemporaryDirectory() as directory:
            self.compile_and_run(Path(directory), prefix + additions('iokit/Kernel/IOUserServer.cpp') + suffix,
                                 language='c++', extra=('-std=c++17',))


if __name__ == '__main__':
    unittest.main()
