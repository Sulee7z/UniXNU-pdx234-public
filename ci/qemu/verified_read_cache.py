"""Isolated bounded VirtIO read cache; every hit still traverses original hashing."""
import hashlib

SOURCE_SHA='b981b7f5d6534916bf1b079ada798ed310fc0651f75ae4c413d735f13e708790'


def once(text,old,new):
    if text.count(old)!=1:raise ValueError('Verified read-cache source anchor differs: '+old[:60])
    return text.replace(old,new)


def adapt(text,*,read_ahead=False):
    if hashlib.sha256(text.encode()).hexdigest()!=SOURCE_SHA:raise ValueError('Qualified current VirtIO source required')
    text=once(text,'#include <mach/mach_vm.h>','#include <mach/mach_vm.h>\n#include "D27VerifiedReadCache.h"')
    text=once(text,'volatile uint32_t native_virtio_read_requests = 0;',
        'volatile uint64_t native_virtio_cache_hits=0,native_virtio_cache_misses=0;\nvolatile uint32_t native_virtio_read_requests = 0;')
    text=once(text,'  unsigned char *verifiedSnapshot = nullptr;',
        '  unsigned char *verifiedSnapshot = nullptr;\n  D27VerifiedReadCache readCache;')
    text=once(text,'  native_virtio_verified_manifest_pointer = verifiedStorage;',
        '''  void *cacheData=IOMalloc(D27VerifiedReadCache::bytes);
  void *cacheTags=IOMalloc(D27VerifiedReadCache::tagBytes);
  if(cacheData && cacheTags)readCache.initialize(cacheData,cacheTags);
  else {
    if(cacheData)IOFree(cacheData,D27VerifiedReadCache::bytes);
    if(cacheTags)IOFree(cacheTags,D27VerifiedReadCache::tagBytes);
  }
  native_virtio_verified_manifest_pointer = verifiedStorage;''')
    text=once(text,'''  IOReturn status = readRawSectors(alignedBegin / 512, span);
  if (status) return status;
  // Snapshot completed DMA before hashing; only this CPU-owned copy is exposed.
  memcpy(verifiedSnapshot, transferMemory->getBytesNoCopy(), span);''',
        '''  const bool cached=readCache.copy(alignedBegin/VR_BLOCK_BYTES,span,verifiedSnapshot);
  if(cached)__atomic_fetch_add(&native_virtio_cache_hits,1,__ATOMIC_RELAXED);
  else {
    __atomic_fetch_add(&native_virtio_cache_misses,1,__ATOMIC_RELAXED);
    IOReturn status = readRawSectors(alignedBegin / 512, span);
    if (status) return status;
    // Snapshot completed DMA before hashing; only this CPU-owned copy is exposed.
    memcpy(verifiedSnapshot, transferMemory->getBytesNoCopy(), span);
  }
  // Cached bytes are always rehashed through the same signed block table below.''')
    text=once(text,'  memmove(verifiedSnapshot, verifiedSnapshot + (begin - alignedBegin), bytes);',
        '  if(!cached)readCache.storeVerified(alignedBegin/VR_BLOCK_BYTES,span,verifiedSnapshot);\n  memmove(verifiedSnapshot, verifiedSnapshot + (begin - alignedBegin), bytes);')
    if read_ahead:
        text=once(text,'''  if (span > transferSize) return kIOReturnBadArgument;
  const bool cached''', '''  if (span > transferSize) return kIOReturnBadArgument;
  // Read ahead only within the immutable authenticated image. Every page of
  // the larger transfer is still hashed before insertion or exposure.
  const uint64_t cacheBegin=begin & ~static_cast<uint64_t>(transferSize-1);
  const uint64_t remaining=capacity*512-cacheBegin;
  const uint64_t cacheBytes=remaining<transferSize?remaining:transferSize;
  if(end-cacheBegin<=cacheBytes) {
    alignedBegin=cacheBegin;span=static_cast<uint32_t>(cacheBytes);
  }
  const bool cached''')
    text=once(text,'  if (verifiedSnapshot) { IOFree(verifiedSnapshot, transferSize); verifiedSnapshot = nullptr; }',
        '''  if(readCache.data)IOFree(readCache.data,D27VerifiedReadCache::bytes);
  if(readCache.tags)IOFree(readCache.tags,D27VerifiedReadCache::tagBytes);
  readCache.initialize(nullptr,nullptr);
  if (verifiedSnapshot) { IOFree(verifiedSnapshot, transferSize); verifiedSnapshot = nullptr; }''')
    return text
