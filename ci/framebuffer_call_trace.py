"""Qualified source overlay for the native D27 framebuffer dispatch boundary.

The source tree is never modified. A consumer stages adapt_source()'s result
beside PdxFramebufferCallTrace.h and recompiles only IOUserClient.cpp using its
recorded arm64e/PAC recipe. The screen archive supplies the optional callbacks.
"""
import hashlib


SOURCE_SHA256 = '9f29c7f0d6c181c220d0f89be6c85e439899059071d7bc62cc817775d174ea94'
HEADER_NAME = 'PdxFramebufferCallTrace.h'
PATCH_NAME = 'framebuffer-call-trace'
INCLUDE_ANCHOR = '#include <IOKit/IOUserClient.h>\n'
INCLUDE_ADDITION = '#include <pexpert/pexpert.h>\n#include "PdxFramebufferCallTrace.h"\n'
METHOD_NAME = 'IOUserClient::callExternalMethod(uint32_t selector, IOExternalMethodArguments * args)'
ORIGINAL_METHOD = '''IOReturn
IOUserClient::callExternalMethod(uint32_t selector, IOExternalMethodArguments * args)
{
\tIOReturn ret;

\tipcEnter(defaultLocking ? (defaultLockingSingleThreadExternalMethod ? kIPCLockWrite : kIPCLockRead) : kIPCLockNone);
\tif (uc2022) {
\t\tret = ((IOUserClient2022 *) this)->externalMethod(selector, (IOExternalMethodArgumentsOpaque *) args);
\t} else {
\t\tret = externalMethod(selector, args);
\t}
\tipcExit(defaultLocking ? (defaultLockingSingleThreadExternalMethod ? kIPCLockWrite : kIPCLockRead) : kIPCLockNone);

\treturn ret;
}'''

HELPER = '''/* PDX framebuffer call trace: boot policy only, no class-private reads. */
static bool
pdx_framebuffer_call_trace_enabled(void)
{
\tstatic int enabled = -1;
\tint value = __atomic_load_n(&enabled, __ATOMIC_RELAXED);
\tif (value < 0) {
\t\tunsigned option = 0;
\t\t(void)PE_parse_boot_argn("first-frame-diag", &option, sizeof(option));
\t\tvalue = option == 1 ? 1 : 0;
\t\t__atomic_store_n(&enabled, value, __ATOMIC_RELAXED);
\t}
\treturn value == 1;
}

'''

LOCAL_ADDITION = '''\tuint64_t pdx_trace_token = 0;
\tuint32_t pdx_trace_output_capacity = 0;
\tconst uint64_t *pdx_trace_output = nullptr;
'''
BEGIN_ADDITION = '''\t/* Observe only the admitted original framebuffer client. Missing observers
\t * leave the ordinary dispatch path without even parsing the boot option. */
\tif (args && pdx_framebuffer_call_begin && pdx_framebuffer_call_end &&
\t    pdx_framebuffer_call_trace_enabled() &&
\t    metaCast("IOMobileFramebufferUserClient")) {
\t\t/* A descriptor input has no length field here. Mark it unavailable
\t\t * rather than issue a new descriptor call just for diagnostics. */
\t\tconst uint64_t pdx_in_bytes = args->structureInputDescriptor ?
\t\t    PDX_FRAMEBUFFER_CALL_SIZE_UNAVAILABLE : args->structureInputSize;
\t\tconst uint64_t pdx_out_bytes = args->structureOutputDescriptor ?
\t\t    args->structureOutputDescriptorSize : args->structureOutputSize;
\t\tpdx_trace_output = args->scalarOutput;
\t\tpdx_trace_output_capacity = args->scalarOutputCount;
\t\tpdx_trace_token = pdx_framebuffer_call_begin(this, getProvider(),
\t\t    selector, args->scalarInputCount, args->scalarInput,
\t\t    pdx_in_bytes, pdx_out_bytes, pdx_trace_output_capacity);
\t}
'''
END_ADDITION = '''\tif (pdx_trace_token) {
\t\tconst uint32_t pdx_out_count = args->scalarOutputCount < pdx_trace_output_capacity ?
\t\t    args->scalarOutputCount : pdx_trace_output_capacity;
\t\tconst uint64_t *pdx_out_scalars = nullptr;
\t\t/* Bound observer reads by entry capacity. A pointer substituted by the
\t\t * callee or a failed output is unavailable, without changing args. */
\t\tif (ret == kIOReturnSuccess && args->scalarOutput == pdx_trace_output) {
\t\t\tpdx_out_scalars = pdx_trace_output;
\t\t}
\t\tconst uint64_t pdx_out_bytes = args->structureOutputDescriptor ?
\t\t    args->structureOutputDescriptorSize : args->structureOutputSize;
\t\tpdx_framebuffer_call_end(pdx_trace_token, ret, pdx_out_count,
\t\t    pdx_out_scalars, pdx_out_bytes);
\t}
'''


def digest(data):
    return hashlib.sha256(data).hexdigest()


def replace_once(text, before, after):
    if text.count(before) != 1:
        raise ValueError('Framebuffer trace anchor changed: ' + before[:100])
    return text.replace(before, after, 1)


def qualify_source(text):
    """Require the exact retained IOUserClient.cpp, not a similar newer file."""
    if digest(text.encode()) != SOURCE_SHA256:
        raise ValueError('Unqualified IOUserClient.cpp source SHA256')
    if text.count(ORIGINAL_METHOD) != 1 or text.count(INCLUDE_ANCHOR) != 1:
        raise ValueError('Qualified IOUserClient.cpp anchors differ')


def adapted_method():
    method = replace_once(ORIGINAL_METHOD, '\tIOReturn ret;\n', '\tIOReturn ret;\n' + LOCAL_ADDITION)
    method = replace_once(method, '\tif (uc2022) {\n', BEGIN_ADDITION + '\tif (uc2022) {\n')
    return replace_once(method, '\tipcExit(', END_ADDITION + '\tipcExit(')


def adapt_source(text):
    qualify_source(text)
    adapted = replace_once(text, INCLUDE_ANCHOR, INCLUDE_ANCHOR + INCLUDE_ADDITION)
    adapted = replace_once(adapted, ORIGINAL_METHOD, HELPER + adapted_method())
    # Prove the envelope is the only source delta. Both original virtual calls,
    # ipcEnter/ipcExit and the single result return remain byte-for-byte intact.
    restored = replace_once(adapted, INCLUDE_ADDITION, '')
    restored = replace_once(restored, HELPER + adapted_method(), ORIGINAL_METHOD)
    if restored != text:
        raise ValueError('Framebuffer trace changed code outside its envelope')
    return adapted


def extracted_code(adapted):
    """Return the exact emitted helper and adapted method for host execution."""
    body = HELPER + adapted_method()
    if adapted.count(body) != 1:
        raise ValueError('Adapted framebuffer method is missing or ambiguous')
    return body
