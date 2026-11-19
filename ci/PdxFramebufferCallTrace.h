// SPDX-License-Identifier: BSD-2-Clause-Patent
// Primitive, optional RAM-observer ABI for native IOUserClient dispatch.
#ifndef PDX_FRAMEBUFFER_CALL_TRACE_H
#define PDX_FRAMEBUFFER_CALL_TRACE_H

#include <stdint.h>

/* Define this before including the header in the screen archive that supplies
 * the callbacks. Only the native caller imports them weakly. */
#ifdef PDX_FRAMEBUFFER_CALL_TRACE_PROVIDER
#define PDX_FRAMEBUFFER_CALL_TRACE_IMPORT
#else
#define PDX_FRAMEBUFFER_CALL_TRACE_IMPORT __attribute__((weak_import))
#endif

#ifdef __cplusplus
extern "C" {
#endif

enum {
    PDX_FRAMEBUFFER_CALL_INPUT_VALUES = 3,
    PDX_FRAMEBUFFER_CALL_OUTPUT_VALUES = 2
};
#define PDX_FRAMEBUFFER_CALL_SIZE_UNAVAILABLE UINT64_MAX

/* Called only for metaCast("IOMobileFramebufferUserClient") with
 * first-frame-diag=1, under the existing IPC lock immediately before dispatch.
 * Counts and sizes come from IOExternalMethodArguments. Inline input size is
 * exact; input via a descriptor reports PDX_FRAMEBUFFER_CALL_SIZE_UNAVAILABLE
 * because this observer never calls a descriptor. Output size is the inline
 * size or the caller-populated structureOutputDescriptorSize capacity.
 * No structure or user address is passed or read.
 *
 * Copy at most min(scalarCount, 3) values synchronously when scalars != NULL.
 * NULL with a nonzero count means unavailable. client/provider are identity
 * tokens, valid during this callback only. The recorder may compare provider
 * with its owned display object and use its independently qualified D27 state
 * helper; this native overlay reads no original class-private offsets.
 *
 * The RAM recorder owns PID/time sampling, token allocation, concurrency,
 * chronological first-failure retention and its bounded latest-record ring.
 * It must not allocate, wait, retain pointers or call back into this client.
 * Returning zero skips the matching end callback. */
extern uint64_t pdx_framebuffer_call_begin(const void *client,
    const void *provider, uint32_t selector, uint32_t scalarCount,
    const uint64_t *scalars, uint64_t inBytes, uint64_t outBytes,
    uint32_t outCount) PDX_FRAMEBUFFER_CALL_TRACE_IMPORT;

/* Called before the existing IPC unlock, with the dispatch's untouched result.
 * outCount is min(returned scalarOutputCount, entry scalarOutputCount). The
 * actual arguments and the dispatch's return value are never changed.
 * outScalars is NULL on failure, pointer replacement, or when the entry buffer
 * is NULL; otherwise copy at most min(outCount, 2) values synchronously.
 * The original scalar buffer belongs to the caller, not to the recorder.
 * outBytes is the returned inline size or structureOutputDescriptorSize.
 * No output descriptor, variable-output object or structure is dereferenced.
 * End must be safe even if records after begin have already wrapped the ring. */
extern void pdx_framebuffer_call_end(uint64_t token, int32_t status,
    uint32_t outCount, const uint64_t *outScalars,
    uint64_t outBytes) PDX_FRAMEBUFFER_CALL_TRACE_IMPORT;

#ifdef __cplusplus
}
#endif

#undef PDX_FRAMEBUFFER_CALL_TRACE_IMPORT
#endif
