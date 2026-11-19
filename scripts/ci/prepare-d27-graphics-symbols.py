#!/usr/bin/env python3
"""Build hash-bound graphics KPI evidence from complete code and mapped vtables."""
import argparse
import collections
import hashlib
import json
from pathlib import Path
import sys

BASE=Path('/mnt/e/UniXNU-sheng27-sony-20261113')


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--out',type=Path,required=True);a=p.parse_args()
    sys.path.insert(0,str(BASE/'strict-graphics-closure-001/XnuPrelink'))
    sys.path.insert(0,str(Path(__file__).resolve().parents[2]/'ci'))
    from kc_image import Image
    from graphics_shape import shape
    raw=Path('/mnt/g/UniXNU-Port/ports/UniXNU-pdx234/.cache/iphone14-ios27/ipsw/24A446/kernelcache.decompressed').read_bytes()
    if hashlib.sha256(raw).hexdigest()!='c28f4fc9b83cde00087e81f890c82d566b9e98b5ac228dfecd83afdf34070445':raise ValueError('D27 hash')
    collection=Image(raw);old=Image(raw,collection.entries['com.apple.kernel'][1]);native=Image((BASE/'pac-abi-native-019/native.macho').read_bytes())
    mapping=json.loads((BASE/'strict-graphics-closure-001/kernel.map.json').read_text())
    missing=json.loads((BASE/'strict-graphics-closure-001/kernel.json').read_text())['missing']
    targets={int(addr,16) for group in missing.values() for addr in group}
    old_starts=old.function_starts();native_starts=native.function_starts();native_names=native.symbols()
    index=collections.defaultdict(list)
    for i,start in enumerate(native_starts[:-1]):
        if start not in native_names:continue
        try:normalized=shape(native.read(start,native_starts[i+1]-start),start)
        except ValueError:continue
        if normalized:index[normalized].append(start)
    rows={}
    def bind(start,name,why):
        if start not in targets:return
        ix=old_starts.index(start);size=old_starts[ix+1]-start
        if start in rows and rows[start]['native_symbol']!=name:raise ValueError('Conflicting reviewed identity')
        rows[start]=dict(original=hex(start),original_size=size,original_sha256=hashlib.sha256(old.read(start,size)).hexdigest(),native_symbol=name,evidence=why)
    # Exact normalized body, not similarity scoring. Tiny leaves require
    # independent semantic/caller evidence below even if only one symbol exists.
    for start in targets:
        if start not in old_starts:continue
        ix=old_starts.index(start);code=old.read(start,old_starts[ix+1]-start);normalized=shape(code,start)
        hits=index.get(normalized,[])
        if normalized and len(normalized)>8 and len(hits)==1 and len(native_names[hits[0]])==1:
            bind(start,native_names[hits[0]][0],
                 'Full function matches unique native normalized instruction sequence, including PAC discriminators and control-flow edges. Only complete compiler AUT check sequences, entry BTI and address relocations normalized in analysis. Emitted PAC remains unchanged.')
    # Direct mapped class+slot evidence; never infer from a nearest data address.
    of,nf=collection.fixups(),native.fixups()
    for key,entry in mapping['data'].items():
        name=entry.get('name') or ''
        if not name.startswith('__ZTV'):continue
        old_base,new_base=int(key,16),int(entry['native'],16)
        for offset in range(16,8192,8):
            left,right=of.get(old_base+offset),nf.get(new_base+offset)
            if not left or not right or left[1:3]!=(1,0) or right[1:3]!=(1,0):break
            if left[0] not in targets or left[1:]!=right[1:]:continue
            names=native_names.get(right[0],[])
            if len(names)==1:
                bind(left[0],names[0],f'Existing mapped class {name}, slot{(offset-16)//8}, original/native chained IA key/address-diversity/type-diversity identical. Concrete native target uniquely named; original method body reviewed with this class API.')
    reviewed={
      0xfffffff00a307f88:('_mach_vm_region','Null map returns KERN_INVALID_ARGUMENT4; flavor10 remapped to9 before region implementation. Native mach_vm_region has the same null guard and flavor translation; vm_user.c VM_REGION_BASIC_INFO_64 compatibility.'),
      0xfffffff00a3597b8:('_ml_page_protection_type','BTI;MOV W0,2;RET lies before ml_nofault_copy. Source reports2 with CONFIG_SPTM,1 with monitor,0 for native non-SPTM; binding preserves platform-specific source implementation.'),
      0xfffffff00a85b380:('__ZN12OSCollection10setOptionsEjjPv','Exact options+0x10 masked-update body, unique full native normalized match; retains old options return.'),
      0xfffffff00a890b60:('__ZN5OSSetC2EPK11OSMetaClass','Sets refcount1, signs OSSet vtable and zeroes members+0x18. Class C2 follows static initialization; equivalent source constructor.'),
      0xfffffff00a890bc0:('__ZN5OSSetD2Ev','Installs OSSet vtable, releases backing members at+0x18 then poisons vptr, no deallocation. Source nondeleting destructor.'),
      0xfffffff00a8f2bf8:('__ZN9IOService15serviceMatchingEPK8OSStringP12OSDictionary','Creates OSSymbol withString from arg0, uses existing dictionary or allocates one, stores symbol under gIOProviderClassKey. Source OSString raw-dictionary overload.'),
      0xfffffff00a90c754:('__ZN9IOService26deRegisterInterestedDriverEPS_','Removes interested-driver registration under PM lock, waits for outstanding driver callback, schedules PM request0x85. Source deRegisterInterestedDriver follows registerInterestedDriver.'),
      0xfffffff00a923668:('__ZN28IOFilterInterruptEventSource26filterInterruptEventSourceEP8OSObjectPFvS1_P22IOInterruptEventSourceiEPFbS1_PS_EP9IOServicei','Class metaclass allocation, forwards5 arguments to init slot34 diversity0xe956; false init releases object. Source function-pointer factory (not block overload).'),
      0xfffffff00a92297c:('__ZN16IODMAEventSource14dmaEventSourceEP8OSObjectP9IOServicePFvS1_PS_P12IODMACommandiyyES8_j','Five-argument factory metaclass atad56e18; invokes init slot38 with IA diversity0x6e5b, which uniquely names IODMAEventSource::init in native vtable. Source factory forwards owner/provider/completion/notification/index; false init releases object.'),
      0xfffffff00a924f18:('__ZN18IOTimerEventSource16timerEventSourceEjP8OSObjectPFvS1_PS_E','Allocates96-byte timer object; dispatches options/owner/action to init slot40 with diversity0x5f4, exactly matching native IOTimerEventSource::init(uint32_t,OSObject*,Action).'),
      0xfffffff00a8d2718:('__ZNK15IORegistryEntry14propertyExistsEPKcPK15IORegistryPlanej','Calls getProperty char-key/plane/options slot38 with diversity0xa20f and converts returned pointer to bool. Native vtable names that exact getProperty overload.'),
      0xfffffff00a91d710:('__ZN13IOEventSource9sleepGateEPvyj','Loads workLoop at+0x30, forwards event/deadline/interruptibility, tail-calls slot34 diversity0x3b96 matching native IOWorkLoop::sleepGate(void*,uint64_t,unsigned).'),
      0xfffffff00a9469e4:('_PEGetModelName','Loads gIOPlatform then dispatches slot181 with diversity0xb584; native IOPlatformExpert vtable names getModelName(char*,int). Original wrapper returns false when platform absent.'),
      0xfffffff00a85b2fc:('__ZN12OSCollection14copyCollectionEP12OSDictionary','Consults cycle dictionary getObject slot37 diversity0x5837 with this as key; retains and returns existing copied collection, or retains this when no dictionary supplied. Source base OSCollection::copyCollection.'),
      0xfffffff00a8eed24:('__ZN9IOService14getServiceRootEv','Loads ad97320, which mapped IOService::setPlatform passes as parent of both gIOResources and gIOUserResources; corresponding source passes gIOServiceRoot. Getter immediately precedes busy-adjust wrapper.'),
      0xfffffff00a9268dc:('__ZN24IOBufferMemoryDescriptor17inTaskWithOptionsEP4taskjmmjj','Allocates buffer descriptor, stores two tag arguments as u16 at+0x30/+0x32, passes task/options/capacity/alignment to initWithPhysicalMask. Six-argument source overload.'),
      0xfffffff00a926e54:('__ZN12IODMACommand16createCopyBufferEjy','Original vtable IA diversity12080 uniquely resolves this native method; body allocates IOBufferMemoryDescriptor in kernel_task with direction/capacity and physical mask0xfffff000.'),
      0xfffffff00a926f1c:('__ZN12IODMACommand24prepareWithSpecificationEPFbPS_NS_9Segment64EPvjEPKNS_14SegmentOptionsEjP8IOMapperyybb','Original vtable IA diversity32676 uniquely matches native overload; rejects active, calls mapped setSpecification, dispatches prepare with supplied range/flags.'),
      0xfffffff00a927270:('__ZN12IODMACommand14OutputLittle32EPS_NS_9Segment64EPvj','Unique full normalized body: writes two32-bit segment words to index*8 and returns true; native source little-endian output callback.'),
      0xfffffff00a927d88:('__ZN12IODMACommand11synchronizeEj','Original vtable diversity10528, handles active state and transfer direction, calls mapped walkAll and complete/prepare; matches source synchronize.'),
      0xfffffff00a9285c4:('__ZN12IODMACommand8completeEbb','Original vtable diversity59410 unique native match; decrements active count, walks copies, unmaps and clears prepared-range state.'),
      0xfffffff00a928f84:('__ZNK12IODMACommand19getMemoryDescriptorEv','Original DMA vtable diversity61480 uniquely matches native getter; loads member+0x48.'),
      0xfffffff00a928f90:('__ZN12IODMACommand21clearMemoryDescriptorEb','Original DMA vtable diversity39986; completes active requests when requested, releases+0x48 descriptor and clears member.'),
      0xfffffff00a929068:('__ZN12IODMACommand19setMemoryDescriptorEPK18IOMemoryDescriptorb','Original DMA vtable diversity2961; replaces retained descriptor+0x48, initializes DMA characteristics, optionally prepares and unwinds on failure.'),
      0xfffffff00a929460:('__ZN12IODMACommand4freeEv','Original DMA free method releases mapper/descriptors and reserved data, destroys DriverKit lock and invokes CompleteDMA then destructor. Source IODMACommand::free.'),
      0xfffffff00a936508:('__ZN18IOMemoryDescriptor26ktraceEmitPhysicalSegmentsEv','Tests debugid0x05410004, requires preparation ID>=2, walks physical segments and returns IOReturn; source ktraceEmitPhysicalSegments exact operation.'),
      0xfffffff00a93da88:('__ZN23IOMultiMemoryDescriptor15withDescriptorsEPP18IOMemoryDescriptorjjb','Allocates112-byte multi descriptor and forwards descriptors/count/direction/asReference to initWithDescriptors; factory preceding setOwnership.'),
      0xfffffff00a967a4c:('__ZN12IOUserClient27copyObjectForPortNameInTaskEP4taskjPP8OSObject','Loads task IPC space with DA schema0x8280; calls mapped iokit lookup kind0x26, stores output raw pointer and returns success/IPCError.'),
      0xfffffff00a967aac:('__ZN12IOUserClient27copyObjectForPortNameInTaskEP4taskjR11OSSharedPtrI8OSObjectE','Same lookup as raw-pointer overload; releases old destination pointee then replaces it. Source shared-pointer overload.'),
      0xfffffff00a93ca18:('__ZN23IOMultiMemoryDescriptor5doMapEP7_vm_mapPyjyy','Existing mapped IOSKRegion vtable offset0x250 has identical PAC schema and uniquely named inherited multi-descriptor target; source doMap.'),
      0xfffffff00a93cd28:('__ZN23IOMultiMemoryDescriptor7prepareEj','Existing mapped IOSKRegion vtable offset0x210 has identical PAC schema and uniquely named multi-descriptor prepare target.'),
      0xfffffff00a93ce2c:('__ZN23IOMultiMemoryDescriptor16getPreparationIDEv','Existing mapped IOSKRegion vtable offset0x1d8 has identical PAC schema and uniquely named multi-descriptor getter.'),
      0xfffffff00a93ceb8:('__ZN23IOMultiMemoryDescriptor18getPhysicalSegmentEyPyj','Existing mapped IOSKRegion vtable offset0x1d0 has identical PAC schema and uniquely named multi-descriptor segment getter.'),
      0xfffffff00a93cfb0:('__ZN23IOMultiMemoryDescriptor12setPurgeableEjPj','Existing mapped IOSKRegion vtable offset0x1b8 has identical PAC schema and uniquely named multi-descriptor purgeable target.'),
      0xfffffff00a1ccee0:('_continuoustime_to_absolutetime','Subtracts mach_absolutetime_asleep, clamps unsigned underflow to0; lies between clock_get_uptime and absolutetime_to_continuoustime; source osfmk/kern/clock.c.'),
      0xfffffff00a25f3a8:('_get_threadtask','Loads thread task pointer at+0x28, authenticates DA diversity0x5ef8, handles null; get_threadtask source and thread task member schema.'),
      0xfffffff00a25fa80:('_get_task_pidsuspended','Reads task pidsuspended flag byte+0x412 bit0; corroborated by sheng reviewed identity through matched IOGPU/IOSurface imports.'),
      0xfffffff00a2a2f38:('_vm_kernel_addrhide','Canonicalizes pointer, checks kernel/static/data ranges, strips PAC for allowed ranges and writes hidden address to arg1. Same API as reviewed sheng mapping.'),
      0xfffffff00a3574e0:('_OSSynchronizeIO','Exact BTI;DSB SY;RET body, between interrupt enable APIs; D27 IOGPU/IOAV import matches sheng reviewed OSSynchronizeIO identity.'),
      0xfffffff00a85a188:('__ZN7OSArrayC2EPK11OSMetaClass','Initializes retainCount1 and installs OSArray signed vptr; follows OSArray static initializer and precedes destructor/operator delete; constructor metadata API.'),
      0xfffffff00a85a1e0:('__ZN7OSArrayD2Ev','OSArray nondeleting destructor, vptr poisoned to-1, preceding class operator delete; native D2 tail-calls OSCollection D2.'),
      0xfffffff00a85a604:('__ZN7OSArray9setObjectERK11OSSharedPtrIK15OSMetaClassBaseE','Reads count+0x14 and sharedptr pointee, tail-dispatches setObject(index,object) at slot30, diversity0x354b; exact source overload in OSArray.cpp.'),
      0xfffffff00a85bb60:('__ZN12OSCollection14iterateObjectsEU13block_pointerFbP8OSObjectE','Initializes two-word iterator, tracks update stamp+0xc, calls block invoke+0x10 for each object and returns whether stamp unchanged; source block overload.'),
      0xfffffff00a85b8c0:('__ZN12OSCollectionD2Ev','Nondeleting destructor poison vptr; located between OSCollection C2 and MetaClass C2; native D2 calls OSObject D2.'),
      0xfffffff00a898d0c:('__ZN11OSSerialize10setIndexedEb','Allocates256-byte OSData index, sets serializer index field+0x50; original IOHID caller and upstream reviewed sheng fixture identify setIndexed; native owns its serializer layout.'),
      0xfffffff00a891100:('__ZN5OSSet9setObjectERK11OSSharedPtrIK15OSMetaClassBaseE','Dereferences sharedptr then tail-calls OSSet setObject slot30 diversity0x5467, matching source overload and sheng reference mapping.'),
      0xfffffff00a8af08c:('__ZN8OSActionD2Ev','Nondeleting destructor poisons vptr; adjacent OSAction C2 and Dispatch in generated IIG order.'),
      0xfffffff00a8b1bf4:('__ZN9IOService20SetProperties_InvokeE5IORPCP15OSMetaClassBasePFiS2_P12OSDictionaryE','Between SearchProperty_Invoke and SetPowerState_Invoke; validates two objects, casts dictionary using its metaclass and calls handler with discriminator0xe4fe, matching generated SetProperties_Invoke.'),
      0xfffffff00a91d650:('__ZN13IOEventSource8openGateEv','Loads workLoop+0x30 then dispatches slot27 diversity0x1ba6; sheng reference maps this exact wrapper to openGate.'),
      0xfffffff00a91d680:('__ZN13IOEventSource9closeGateEv','Loads workLoop+0x30 then dispatches slot28 diversity0x3946; sheng reference maps exact wrapper to closeGate.'),
      0xfffffff00a91fd5c:('__ZN13IOCommandGateD2Ev','Nondeleting destructor poisons vptr; after IOCommandGate C1/C2 before delete; own superclass D2 chain.'),
      0xfffffff00a924c88:('__ZN18IOTimerEventSourceD2Ev','Nondeleting destructor poisons vptr; bounded by class C1/C2 and delete.'),
      0xfffffff00a9264d4:('__ZN24IOBufferMemoryDescriptorD2Ev','Nondeleting destructor installs class then base vptr and releases fields+0x90/+0x18 before poisoning; class delete follows.'),
      0xfffffff00a929d54:('__ZN12IODMACommandD2Ev','Nondeleting destructor installs DMA class vptr, releases descriptor+0x48 and mapper+0x40, poisons vptr; adjacent C1/C2/delete.'),
      0xfffffff00a92be3c:('__ZN8IOMapperD2Ev','Nondeleting destructor poisons vptr; between IOMapper C2 and MetaClass C2.'),
      0xfffffff00a93b980:('__ZN18IOMemoryDescriptor10setContextEP8OSObject','Moves object to arg2, loads shared context key and tail-calls sharing-context API; upstream reviewed sheng identity.'),
      0xfffffff00a93b994:('__ZN18IOMemoryDescriptor15getDescriptorIDEv','Ensures descriptor ID then returns reserved+0x18 or0; upstream reviewed sheng identity.'),
      0xfffffff00a96624c:('__ZN12IOUserClient19setAsyncReference64EPyP8ipc_portyyP4task','Stores port and callback/refcon words; tests task map bounds to encode pointer width; five-argument overload immediately after four-argument setAsyncReference64.'),
      0xfffffff00a9737f8:('__ZN17IOSharedDataQueueD2Ev','Nondeleting destructor poisons vptr; follows shared queue C1/C2 before delete.'),
      0xfffffff00a973f0c:('_IOCircularDataQueueDestroy','Validates pointer-to-queue, releases reserved descriptor+0x38, frees64-byte queue, nulls caller pointer; source destroy API between CreateWithEntries and CopyMemoryDescriptor.'),
      0xfffffff00a99bedc:('__ZN24IOProviderPropertyMergerD2Ev','Nondeleting destructor poisons vptr; between class C1/C2 and delete.'),
    }
    symbols={name for group in native_names.values() for name in group}
    for start,(name,evidence) in reviewed.items():
        if 'requires review' in evidence:continue
        if name not in symbols:raise ValueError('Missing native '+name)
        bind(start,name,evidence)
    data=[]
    for addr,name,evidence in [
        (0xfffffff007c21670,'__ZN9IOCommand9metaClassE','Constant pointer targets ad56ee0; referenced by IOCommand static initializer and IODMACommand superclass constructor, verified from original instructions and matched class names.'),
        (0xfffffff007c2e270,'__ZN8OSAction9metaClassE','Constant pointer targets ad563f0; mapped OSAction::getMetaClass returns this metaobject and generated IIG dispatches compare against it.'),
        (0xfffffff007c2e328,'__ZN12OSCollection9metaClassE','Constant pointer targets ad55db0, superclass argument in mapped OSArray/OSDictionary/OSSet static initializers and OSCollection own initializer.'),
        (0xfffffff007c2e330,'__ZN8OSObject9metaClassE','Constant pointer targets ad586b8, superclass in mapped OSCollection/OSBoolean/OSData and other direct OSObject subclass constructors.'),
        (0xfffffff00ad57dd0,'_gIOFirstPublishNotification','Mapped IOService::initialize initializes this key and doServiceMatch/installNotification use it; also independently recovered via sheng IOAV imported pointer.'),
        (0xfffffff00acf3ce8,'_kext_assertions_enable','IOHIDFamily GOT008009e30 points here. Callers test32-bit flag and null objects; enabled failures branch to BRK0xbffc with __assert descriptors. Descriptor008009488 names IOHIDElementProcessor.cpp:1054 and expression me. Exactly APPLE_KEXT_ASSERTIONS mach_assert_enabled() in osfmk/kern/assert.h; bind to native live flag, do not disable checks.'),
    ]:
        if name not in symbols:raise ValueError(name)
        data.append(dict(original=hex(addr),native_symbol=name,addend=0,evidence=evidence))
    payload=dict(inputs=dict(kernelcache_sha256=hashlib.sha256(raw).hexdigest(),entry='com.apple.kernel'),functions=list(rows.values()),data=data)
    a.out.parent.mkdir(parents=True,exist_ok=True)
    if a.out.exists():raise ValueError('Keep prior evidence')
    a.out.write_text(json.dumps(payload,indent=2)+'\n');print('Hash-bound identities',len(rows),'remaining addresses',len(targets-set(rows)))


if __name__=='__main__':main()
