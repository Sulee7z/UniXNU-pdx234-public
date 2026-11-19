"""New immutable-source069 adaptations over frozen067 board and selected owners."""
from __future__ import annotations

def once(text,old,new):
    if text.count(old)!=1:raise ValueError('Source-qualified069 anchor differs: '+old[:120])
    return text.replace(old,new)

def armcpu(text):
    text=once(text,'#define ARMCPU_SPI_SLOTS 24','extern "C" bool sony_radio_lpi_dispatch(uint32_t);\n#define ARMCPU_SPI_SLOTS 24')
    # ID1020..1023 are spurious/reserved, not every larger number. Physical LPIs
    # are dispatched before the distributor array path; EOIR still uses rawIAR.
    if 'if ((id & 0xffffff) >= 1020)' in text:
        text=once(text,'if ((id & 0xffffff) >= 1020)','if ((id & 0xffffff) >= 1020 && (id & 0xffffff) <= 1023)')
    elif 'if (id >= 1020)' in text:
        text=once(text,'if (id >= 1020)','if (id >= 1020 && id <= 1023)')
    else:raise ValueError('Actual ArmCpu spurious guard differs')
    text=once(text,'      if (spiDispatch (intid)) {','      if (intid >= 8192 && sony_radio_lpi_dispatch(intid)) {\n      } else if (spiDispatch (intid)) {')
    # Never index GICD arrays with an unhandled LPI.
    text=once(text,'      } else if (intid >= 32 && gDist != 0) {','      } else if (intid >= 8192) {\n        armcpu_spi_unhandled=armcpu_spi_unhandled+1;armcpu_spi_unhandled_id=intid;\n      } else if (intid >= 32 && gDist != 0) {')
    return text

def touch(text):
    text=once(text,'IOLock *gSmmuConfigLock;','extern "C" int sony_shared_config_lock(void);\nextern "C" void sony_shared_config_unlock(void);')
    text=once(text,'SonySmmuGuard():held(gSmmuConfigLock!=nullptr){if(held)IOLockLock(gSmmuConfigLock);}',
              'SonySmmuGuard():held(sony_shared_config_lock()==0){}')
    text=once(text,'~SonySmmuGuard(){if(held)IOLockUnlock(gSmmuConfigLock);}',
              '~SonySmmuGuard(){if(held)sony_shared_config_unlock();}')
    text=once(text,'    gSmmuConfigLock=IOLockAlloc();if(!gSmmuConfigLock){fail(-8);return;}','    // Shared069 config mutex is acquired by the actual SMMU/GCC operations.')
    # Primary shared GCC vote words join the same lock; no new I2C sequence.
    text=once(text,'        vote.write(0x18,vote.read(0x18)|1u);',
              '        {SonySmmuGuard guard;if(!guard.ready())return false;vote.write(0x18,vote.read(0x18)|1u);}')
    text=once(text,'        vote.write(8,vote.read(8)|kVote);',
              '        {SonySmmuGuard guard;if(!guard.ready())return false;vote.write(8,vote.read(8)|kVote);}')
    return text

def wifi(text):
    text=once(text,'#include "SonyWcnBoard.h"','#include "SonyWcnBoard.h"\n#include "SonyBoard2.h"\n'
              'extern "C" int sony069_wifi_dma_prepare(void);\nextern "C" bool sony069_wifi_dma_faulted(void);')
    # Replace inherited storage allocation globals with the actual069 dedicated
    # WLAN128MiB translated DMA and separateMSI IOVA mapping supplied by provider.
    text=text.replace('native_ufs_extra_','sony069_wifi_dma_')
    # DMA is configured only while WLAN_EN/PERST are asserted low, not before
    # thread creation while an inherited endpoint could still issue requests.
    start=text.index('    if(!ready && stage>=5 && (&sony069_wifi_dma_va==nullptr')
    end=text.index('    if(ready)',start)
    text=text[:start]+text[end:]
    text=once(text,'    IOSleep(150);\n',
              '    IOSleep(150);\n    unsigned stage=0;PE_parse_boot_argn("wifi",&stage,sizeof(stage));\n'
              '    if(stage>=5){\n'
              '        if((t[kPerst*0x1000/4]&(1u<<9))==0 || (t[kWlanEn*0x1000/4]&(1u<<9))==0 ||\n'
              '           ((t[(kPerst*0x1000+4)/4]|t[(kWlanEn*0x1000+4)/4])&3u)){\n'
              '            native_wifi_stats[0]=(uint32_t)-EIO;return;\n'
              '        }\n'
              '        const int dmaError=sony069_wifi_dma_prepare();\n'
              '        if(dmaError){native_wifi_stats[0]=(uint32_t)-dmaError;return;}\n'
              '    }\n')
    text=once(text,'    if(!ready && stage>=5)ready=sony_wcn_wifi_inputs_ready();\n','')
    text=once(text,'    thread_set_thread_name(current_thread(), "wifi");',
              '''    thread_set_thread_name(current_thread(), "wifi");
    if (reinterpret_cast<uintptr_t>(arg) >= 5) {
        uint32_t variant=1;
        if(PE_parse_boot_argn("wifi-fw",&variant,sizeof(variant)) && variant!=1){native_wifi_stats[0]=(uint32_t)-ENOTSUP;return;}
        int ready=EAGAIN;
        for(unsigned i=0;i<240 && ready==EAGAIN;++i){
            ready=sony_wcn_wifi_inputs_ready();
            if(ready==EAGAIN)IOSleep(500);
        }
        if(ready){native_wifi_stats[0]=(uint32_t)-ready;native_wifi_logf(3,"wifi: installed firmware rejected: %d",ready);return;}
    }''')
    text=once(text,'    bzero(gArena.va, gArena.bytes);\n','') # arenaAlloc zeros each owned buffer
    text=once(text,'    n = (n + 63) & ~(size_t)63;',
              '    if(!n || n>gArena.bytes)return nullptr;\n    n = (n + 63) & ~(size_t)63;')
    text=once(text,'''uint64_t pDmaMap(void *p, size_t, int) {
    if ((uint8_t *)p < gArena.va || (uint8_t *)p >= gArena.va + gArena.bytes) return 0;
    return gArena.iova + ((uint8_t *)p - gArena.va);
}
void pDmaSync(uint64_t, size_t, int) {}''','''uint64_t pDmaMap(void *p, size_t bytes, int) {
    const uintptr_t start=(uintptr_t)gArena.va, address=(uintptr_t)p;
    if (!bytes || address<start || address-start>=gArena.bytes || bytes>gArena.bytes-(address-start)) return 0;
    return gArena.iova + (address-start);
}
// PCIe0 has dma-coherent in the captured Sony FDT. Order CPU and DMA accesses
// to coherent memory, including doorbells, without cleaning unrelated lines.
void pDmaSync(uint64_t bus, size_t bytes, int) {
    if(bus>=gArena.iova && bus-gArena.iova<gArena.bytes && bytes<=gArena.bytes-(bus-gArena.iova))
        __asm__ volatile("dsb sy" ::: "memory");
}''')
    text=once(text,'        const uint64_t began = pNowNs();\n        const int busy = nw_wifi_step();',
              '''        if(sony069_wifi_dma_faulted()){
            native_wifi_logf(3,"wifi: owned SMMU context fault; stopping the radio stack");
            st[0]=(uint32_t)-EIO;nw_wifi_stop();return;
        }
        const uint64_t began = pNowNs();
        const int busy = nw_wifi_step();''')
    text=once(text,'    if (!strcmp(base, "wlan_mac.bin")) return macFile(data, size);',
              '    if (!strcmp(base, "wlan_mac.bin")) return macFile(data, size);\n'
              '    if (!strcmp(base,"board-2.bin")){int e=sony069_wifi_board2(data,size);return e?-e:0;}')
    return text

def qmi(text):
    # Feed exact firmware-supplied chip/board/soc identity to runtime board2
    # before a board request. No guessed board key, no core success stub.
    old='\tath12k_info(ab, "chip_id 0x%x chip_family 0x%x board_id 0x%x soc_id 0x%x\\n",'
    text=once(text,old,'\tif(!resp.chip_info_valid || !resp.board_info_valid || !resp.soc_info_valid ||\n'
              '\t   ab->id.vendor!=0x17cb || ab->id.device!=0x1107){ret=-ENODEV;goto out;}\n'
              '\t{ extern int sony069_wifi_qmi_identity(u32,u32,u32);\n'
              '\t  ret=sony069_wifi_qmi_identity(ab->qmi.target.chip_id,ab->qmi.target.board_id,ab->qmi.target.soc_id);\n'
              '\t  if(ret){ret=-ret;goto out;} }\n'+old)
    return text

def ath12k_core(text):
    import re
    def extract(source,name):
        match=re.search(r'(?m)^int '+re.escape(name)+r'\s*\(',source)
        if not match:raise ValueError('Locked Ath12k function missing: '+name)
        opening=source.index('{',match.end());depth=0;quote=None;escape=False
        for at in range(opening,len(source)):
            c=source[at]
            if quote:
                if escape:escape=False
                elif c=='\\':escape=True
                elif c==quote:quote=None
                continue
            if c in ('"',"'"):quote=c
            elif c=='{':depth+=1
            elif c=='}':
                depth-=1
                if depth==0:return match.start(),at+1
        raise ValueError('Unterminated Ath12k function: '+name)
    def edit(source,name,transform):
        first,last=extract(source,name);return source[:first]+transform(source[first:last])+source[last:]
    def request(fragment,needle,kind,fallback):
        if fragment.count(needle)!=1:raise ValueError('Expected one selected Ath12k API2 request: '+needle)
        failure='return ret;' if kind==0 else 'goto exit;'
        generator='ath12k_core_create_fallback_board_name' if kind==0 else 'ath12k_core_create_bus_type_board_name'
        call=(f'\tret = {generator}(ab, {fallback}, sizeof({fallback}));\n'
              f'\tif (ret) {{ {failure} }}\n'
              '\t{ extern int sony069_wifi_board_key(unsigned,const char *);\n'
              f'\t  int keyError = sony069_wifi_board_key({kind}, boardname);\n'
              f'\t  if (!keyError) keyError = sony069_wifi_board_key({kind}, {fallback});\n'
              f'\t  if (keyError) {{ ret = -keyError; {failure} }} }}\n')
        return fragment.replace(needle,call+needle,1)
    def bdf(fragment):
        return request(fragment,'\tret = ath12k_core_fetch_board_data_api_n(ab, bd, boardname,',0,'fallback_boardname')
    text=edit(text,'ath12k_core_fetch_bdf',bdf)
    def regdb(fragment):
        return request(fragment,'\tret = ath12k_core_fetch_board_data_api_n(ab, bd, boardname,',1,'default_boardname')
    return edit(text,'ath12k_core_fetch_regdb',regdb)


def apps_smmu(text):
    # Linux ARM SMMUv2 stage1 allocation starts at NUMS2CB. Reserve the last
    # bank for the platform's existing UFS/touch/UART bypass owner.
    return once(text,'    for (unsigned i = 1; i < banks; ++i) {',
                '    const unsigned stage2_only = (id1 >> 16) & 255;\n'
                '    for (unsigned i = stage2_only > 1 ? stage2_only : 1; i + 1 < banks; ++i) {')

def raw_firmware(text):
    text=once(text,'#include "WifiFirmware.h"','#include "WifiFirmware.h"\nextern int sony069_wifi_verify_firmware(const char *,const uint8_t *,size_t);')
    text=once(text,'''  /* join.txt: the unattended-test network file, present only in a build made with UNIXNU_WIFI_JOIN and read only with wifi-aj=1. */
  if (strcmp(name, "amss.bin") && strcmp(name, "amss2.bin") &&
      strcmp(name, "m3.bin") && strcmp(name, "board-2.bin") && strcmp(name, "join.txt")) return ENOENT;''',
              '''  if (!name || (strcmp(name,"amss.bin") && strcmp(name,"m3.bin") &&
      strcmp(name,"sony-board.elf") && strcmp(name,"sony-regdb.bin"))) return ENOENT;''')
    text=once(text,'  if (error) { if (buffer) IOFreeData(buffer, length); return error; }',
              '  if (!error) error=sony069_wifi_verify_firmware(name,buffer,length);\n'
              '  if (error) { if (buffer) IOFreeData(buffer, length); return error; }')
    return text+'\nint sony069_wifi_read_raw(const char *name,uint8_t **data,size_t *size){return sony_wifi_firmware_read(name,data,size);}\n'

def bluetooth_firmware(text):
    text=once(text,'#include "BluetoothFirmware.h"','#include "BluetoothFirmware.h"\nextern int sony069_bt_verify_firmware(const char *,const uint8_t *,size_t);')
    return once(text,'    if(error){if(buffer)IOFreeData(buffer,length);return error;}',
                '    if(!error)error=sony069_bt_verify_firmware(name,buffer,length);\n'
                '    if(error){if(buffer)IOFreeData(buffer,length);return error;}')

def bluetooth(text):
    text=once(text,'    if(!ready)ready=sony_wcn_bluetooth_inputs_ready();\n','')
    text=once(text,'    while(native_gpu_addon_stage<1)waitUntil(nullptr,nowNs(nullptr)+10000000ULL);\n','')
    text=once(text,
        '    thread_set_thread_name(current_thread(),"bluetooth");',
        '''    thread_set_thread_name(current_thread(),"bluetooth");
    int ready=EAGAIN;
    for(unsigned i=0;i<240 && ready==EAGAIN;++i){
        ready=sony_wcn_bluetooth_inputs_ready();
        if(ready==EAGAIN)IOSleep(500);
    }
    if(ready){
        printf("[sony069-bt] installed firmware rejected: %d\\n",ready);
        bootFailure069(ready);return;
    }''')
    text=once(text, 'void worker(void *,wait_result_t) {', '''// Complete the native boot result even if the worker never reaches powerOn.
// Otherwise kern.qbt_boot retains its initial -1 (pending) state.
void bootFailure069(int error) {
    native_bluetooth_stats[0]=3;
    native_bluetooth_stats[1]=(uint64_t)(int64_t)-error;
    qbt_transport_boot_result(error,nullptr,0);
}
void worker(void *,wait_result_t) {''')
    text=once(text, 'bt.core=qbt_create(&ops);if(!bt.core){native_bluetooth_stats[0]=3;native_bluetooth_stats[1]=(uint64_t)(int64_t)-ENOMEM;return;}',
              'bt.core=qbt_create(&ops);if(!bt.core){bootFailure069(ENOMEM);return;}')
    text=once(text, 'if(ready){native_bluetooth_stats[0]=3;native_bluetooth_stats[1]=(uint64_t)(int64_t)-ready;return;}',
              'if(ready){bootFailure069(ready);return;}')
    text=once(text, 'if(!address()){native_bluetooth_stats[0]=3;native_bluetooth_stats[1]=(uint64_t)(int64_t)-ENOENT;return;}',
              'if(!address()){bootFailure069(ENOENT);return;}')
    return once(text, 'else {native_bluetooth_stats[0]=3;native_bluetooth_stats[1]=(uint64_t)(int64_t)-ENOMEM;__atomic_store_n(&bt.started,0u,__ATOMIC_RELEASE);}',
                'else {bootFailure069(ENOMEM);__atomic_store_n(&bt.started,0u,__ATOMIC_RELEASE);return;}')

def ufs(text):
    # The old block programs SID1401 with an earlier ad-hoc table.069 owns that
    # exact stream and MSI device page after reset, with official picker/tables.
    return once(text,'  if (PE_parse_boot_argn ("wifi", &wifi, sizeof (wifi)) && wifi >= 2) {',
                '  if (false && PE_parse_boot_argn ("wifi", &wifi, sizeof (wifi)) && wifi >= 2) { /* SID1401 owned by Sony069 provider */')
