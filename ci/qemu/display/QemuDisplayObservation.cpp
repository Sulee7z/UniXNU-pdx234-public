// SPDX-License-Identifier: BSD-2-Clause-Patent
// Passive D27 observations. No state, IOSurface, descriptor or PM mutation.
#include <IOKit/IOService.h>
#include <IOKit/IOMemoryDescriptor.h>
#include <libkern/libkern.h>
#include "QemuDisplayOffsets.h"

extern "C" {
IOMemoryDescriptor *native_legacy_surface_descriptor(OSObject *);
uint64_t native_legacy_surface_width(OSObject *), native_legacy_surface_height(OSObject *);
uint64_t native_legacy_surface_stride(OSObject *);
uint32_t native_legacy_surface_format(OSObject *), native_legacy_surface_planes(OSObject *);

struct QemuDisplayObservation {
    uint64_t sequence, display, surface, descriptor, descriptorBytes;
    uint64_t width, height, stride, current, pending;
    uint32_t event, requested, powered, format, planes, surfaceValid;
};
volatile uint32_t native_qemu_display_observation_count;
QemuDisplayObservation native_qemu_display_observations[32];

void native_qemu_display_observe(unsigned event, IOService *display) {
    if(!display)return;
    // Invoked at existing owned callbacks, where the original family retains
    // display and its default surface. Never prepare or map the descriptor.
    auto bytes=reinterpret_cast<const unsigned char *>(display);
    QemuDisplayObservation record={};
    record.event=event;record.display=reinterpret_cast<uintptr_t>(display);
    memcpy(&record.requested,bytes+kQemuRequested,4);
    memcpy(&record.powered,bytes+kQemuPowered,4);
    memcpy(&record.current,bytes+kQemuCurrent,8);
    memcpy(&record.pending,bytes+kQemuPending,8);
    OSObject *surface=nullptr;
    memcpy(&surface,bytes+kQemuDefaultSurface,sizeof(surface));
    record.surface=reinterpret_cast<uintptr_t>(surface);
    if(surface && surface->metaCast("IOSurface")) {
        IOMemoryDescriptor *memory=native_legacy_surface_descriptor(surface);
        record.descriptor=reinterpret_cast<uintptr_t>(memory);
        record.width=native_legacy_surface_width(surface);
        record.height=native_legacy_surface_height(surface);
        record.stride=native_legacy_surface_stride(surface);
        record.format=native_legacy_surface_format(surface);
        record.planes=native_legacy_surface_planes(surface);
        if(memory && memory->metaCast("IOMemoryDescriptor")) {
            record.descriptorBytes=memory->getLength();
            record.surfaceValid=record.width && record.height && record.width<=16384 && record.height<=16384 &&
                record.stride>=record.width*4 && record.stride<=UINT64_MAX/record.height &&
                record.descriptorBytes>=record.stride*record.height && record.format==0x42475241 && !record.planes;
        }
    }
    const uint32_t index=__atomic_fetch_add(&native_qemu_display_observation_count,1,__ATOMIC_RELAXED);
    // Keep the early activation/surface transitions; later callbacks only
    // advance the count. An empty record is never interpreted as a measurement.
    if(index<32) {
        native_qemu_display_observations[index]=record;
        __atomic_store_n(&native_qemu_display_observations[index].sequence,uint64_t(index)+1,__ATOMIC_RELEASE);
    }
}
}
