"""Qualified source-only D27 display lifecycle and observation overlay."""
import hashlib
import struct

GOP_SHA256 = '465f5ebfe1df7228c66ecebd2b17a9971a7af64882efd132a907b1b0abacb78a'
PROBE_SHA256 = '2710262ae6bcbdaa92cf8b2c40116f3c4b85a02e19233fe92e35ecc6cd3adb1e'
CACHE_SHA256 = 'c28f4fc9b83cde00087e81f890c82d566b9e98b5ac228dfecd83afdf34070445'
STATE_SHA256 = 'e317273a4a13df025929fa80b0a8d30b8a1bab6f4d3997127e911af6944740ba'


def digest(data):
    return hashlib.sha256(data).hexdigest()


def replace_once(text, old, new):
    if text.count(old) != 1:
        raise ValueError('Display overlay anchor changed: ' + old[:80])
    return text.replace(old, new, 1)


def qualify(abi, cache):
    """Check the actual D27 setter before exposing its two state fields."""
    if abi['kernelcache_sha256'] != CACHE_SHA256 or digest(cache) != CACHE_SHA256:
        raise ValueError('Display observation requires the original D27 cache')
    if abi['display']['current'] != 6720 or abi['display']['head'] != 6728:
        raise ValueError('Reviewed D27 queue layout changed')
    address = int(abi['slots'][abi['methods']['applyStateRequest']][0], 16)
    offset = 32
    body = None
    for _ in range(struct.unpack_from('<I', cache, 16)[0]):
        command, size = struct.unpack_from('<II', cache, offset)
        if command == 0x19:
            va, _, fileoff, filesize = struct.unpack_from('<QQQQ', cache, offset + 24)
            if va <= address and address + 132 <= va + filesize:
                body = cache[fileoff + address - va:fileoff + address - va + 132]
        offset += size
    if body is None or digest(body) != STATE_SHA256:
        raise ValueError('D27 applyStateRequest instruction evidence changed')
    # Exact setter: ldr/str requested at +0x1c0c, powered at +0x1c10.
    words = struct.unpack('<33I', body)
    if (words[6], words[9], words[14], words[20]) != (0xb95c0c0a, 0xb91c0c09, 0xb95c100a, 0xb91c1009):
        raise ValueError('D27 power field instructions changed')
    return dict(kernelcache_sha256=CACHE_SHA256, state_method=hex(address),
                state_method_bytes=132, state_method_sha256=STATE_SHA256,
                current=abi['display']['current'], head=abi['display']['head'],
                requested=0x1c0c, powered=0x1c10,
                generation_and_frame_offsets='unqualified: report UINT32_MAX, never read old offsets')


def apply_gop(text):
    if digest(text.encode()) != GOP_SHA256:
        raise ValueError('Unreviewed GOP source revision')
    text = replace_once(text, '''        if(!startDisplay(provider))return false;
        publishOneLayer();''', '''        // The original family registers this service inside start(). Publish its
        // mandatory single-layer contract before any client can discover it.
        if(!publishOneLayer() || !startDisplay(provider))return false;''')
    text = replace_once(text, '''    void publishOneLayer() {
        OSDictionary *layers=OSDictionary::withCapacity(1);
        OSNumber *count=OSNumber::withNumber(1ULL,32);
        if(layers && count && layers->setObject("MaxNumLayers",count))setProperty("IOMFBNumLayers",layers);
        OSSafeReleaseNULL(count);OSSafeReleaseNULL(layers);
    }''', '''    bool publishOneLayer() {
        OSDictionary *layers=OSDictionary::withCapacity(1);
        OSNumber *count=OSNumber::withNumber(1ULL,32);
        const bool published=layers && count && layers->setObject("MaxNumLayers",count) &&
                             setProperty("IOMFBNumLayers",layers);
        OSSafeReleaseNULL(count);OSSafeReleaseNULL(layers);
        return published;
    }''')
    first = text.index('            // The compositor renders the next frame only after this swap retires')
    last = text.index('            if(early==1 && retireSwap(request,true))', first)
    text = text[:first] + '''            // Keep the family's IOSurface ownership until the matching copy completion.
            // early-retire=1 retains the upstream experimental overlap option; its
            // memory-descriptor retain alone does not prevent producer reuse, so it
            // is opt-in and is not the Sony completion contract.
            unsigned early=0;PE_parse_boot_argn("early-retire",&early,sizeof(early));
''' + text[last:]
    return text


def apply_probe(text, fields):
    if digest(text.encode()) != PROBE_SHA256:
        raise ValueError('Unreviewed display probe source revision')
    text = replace_once(text, 'volatile uint32_t native_legacy_client_calls,native_legacy_client_type;',
                        '''// client_calls counts open attempts; successes require status zero and a client.
volatile uint32_t native_legacy_client_calls,native_legacy_client_type;
volatile uint32_t native_legacy_client_successes;''')
    text = replace_once(text, '''    memcpy(&current,bytes+5472,8);memcpy(&pending,bytes+5480,8);
    memcpy(&completed,bytes+5820,4);memcpy(&presented,bytes+5824,4);memcpy(&frames,bytes+252,4);''',
                        f'''    memcpy(&current,bytes+{fields['current']},8);memcpy(&pending,bytes+{fields['head']},8);
    // D27 queue offsets are fixture-qualified. Generation/frame fields are not;
    // UINT32_MAX means unavailable, not a measured zero or a fabricated trace.
    completed=presented=frames=UINT32_MAX;''')
    text = replace_once(text, '''                const unsigned char *object=reinterpret_cast<const unsigned char *>(native_legacy_object);
                e.done=e.presented=0;if(object){memcpy(&e.done,object+5820,4);memcpy(&e.presented,object+5824,4);}''',
                        '                e.done=e.presented=UINT32_MAX; // D27 generation fields unqualified.')
    text = replace_once(text, '[5820]=%x [5824]=%x', 'generation-unavailable=%x/%x')
    first = text.index('// The display object\'s state words the original wait selector tests')
    last = text.index('extern "C" unsigned native_legacy_clients_dump', first)
    text = text[:first] + f'''// Only the two state words qualified from the selected D27 applyStateRequest.
extern "C" unsigned native_legacy_state_words(char *out,unsigned cap) {{
    if(!out || !cap)return 0;
    out[0]=0;
    const unsigned char *object=reinterpret_cast<const unsigned char *>(native_legacy_object);
    if(!object)return 0;
    uint32_t requested=0,powered=0;
    memcpy(&requested,object+{fields['requested']},4);memcpy(&powered,object+{fields['powered']},4);
    int size=snprintf(out,cap,"D27 requested=%x powered=%x (generation unavailable)",requested,powered);
    return size<0?0:(unsigned)size<cap?(unsigned)size:cap-1;
}}
''' + text[last:]
    text = replace_once(text, '    unsigned at=0;out[0]=0;\n    for(unsigned c=0;c<seenClientCount',
                        '''    if(!out || !cap)return 0;
    int size=snprintf(out,cap,"opens attempts=%u successes=%u; selector tracing unavailable on PAC builds\\n",
        native_legacy_client_calls,native_legacy_client_successes);
    unsigned at=size<0?0:(unsigned)size<cap?(unsigned)size:cap-1;
    for(unsigned c=0;c<seenClientCount''')
    text = replace_once(text, '    if(client && !status)interpose(client,native_legacy_client_pid);',
                        '''    if(client && !status) {
        __atomic_fetch_add(&native_legacy_client_successes,1,__ATOMIC_RELAXED);
        interpose(client,native_legacy_client_pid);
    }''')
    return text
