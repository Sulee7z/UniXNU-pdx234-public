/* SPDX-License-Identifier: BSD-2-Clause-Patent */
#include "sony_radio069_host.h"
#include "WifiFirmware.h"
#include "BluetoothFirmware.h"
static unsigned assertions,verified,read_files,refused_metadata;
typedef int (*reader_t)(const char *,uint8_t **,size_t *);
static void failed(reader_t read,const char *name,int expected) {
    uint8_t *data=(void *)1;size_t size=1;
    int result=read(name,&data,&size);
    if(result!=expected)fprintf(stderr,"name=%s result=%d expected=%d\n",name?name:"NULL",result,expected);
    CHECK(result==expected && !data && !size && !host_live_allocations);
    CHECK(host_closes<=host_opens);assertions++;
}
static void files_test(void) {
    CHECK(host_file_count==53);
    for(size_t i=0;i<host_file_count;i++) {
        struct host_fixture *f=&host_files[i];
        int (*verify)(const char *,const uint8_t *,size_t)=f->wifi?sony069_wifi_verify_firmware:sony069_bt_verify_firmware;
        reader_t read=f->wifi?sony_wifi_firmware_read:sheng_bt_firmware_read;
        CHECK(!verify(f->name,f->data,f->bytes));verified++;
        CHECK(verify(f->name,f->data,f->bytes-1)==EINVAL);
        CHECK(verify(NULL,f->data,f->bytes)==EINVAL);
        CHECK(verify(f->name,NULL,f->bytes)==EINVAL);
        f->data[f->bytes/2]^=1;
        CHECK(verify(f->name,f->data,f->bytes)==EAUTH);
        f->data[f->bytes/2]^=1;
        host_reset();
        if(strstr(f->name,".ver")) {
            failed(read,f->name,ENOENT);CHECK(!host_opens);refused_metadata++;continue;
        }
        uint8_t *data=NULL;size_t size=0;
        CHECK(!read(f->name,&data,&size));CHECK(size==f->bytes && !memcmp(data,f->data,size));
        CHECK(host_opens==1 && host_closes==1 && host_reads==1);
        if(f->wifi)IOFreeData(data,size);else sheng_bt_firmware_release(data,size);
        CHECK(!host_live_allocations);read_files++;
        host_reset();host_fault.tamper=1;failed(read,f->name,EAUTH);
        CHECK(host_opens==1 && host_closes==1 && host_reads==1);
    }
}
static void reader_errors(reader_t read,const char *name,size_t limit) {
    host_reset();native_gpu_addon_stage=0;failed(read,name,EAGAIN);CHECK(!host_opens && !host_allocations);
    host_reset();native_gpu_addon_stage=-1;failed(read,name,EAGAIN);CHECK(!host_opens);
    host_reset();host_fault.open_error=EACCES;failed(read,name,EACCES);CHECK(!host_closes);
    host_reset();host_fault.missing=name;failed(read,name,ENOENT);CHECK(!host_closes);
    host_reset();host_fault.getattr_error=EIO;failed(read,name,EIO);CHECK(host_closes==1 && !host_allocations);
    host_reset();host_fault.vtype=2;failed(read,name,EINVAL);CHECK(host_closes==1 && !host_allocations);
    host_reset();host_fault.attr_size=0;failed(read,name,EINVAL);CHECK(!host_allocations);
    host_reset();host_fault.attr_size=(int64_t)limit+1;failed(read,name,EINVAL);CHECK(!host_allocations);
    host_reset();host_fault.attr_size=INT64_MAX;failed(read,name,EINVAL);CHECK(!host_allocations);
    host_reset();host_fault.fail_allocation=1;failed(read,name,ENOMEM);CHECK(host_closes==1 && !host_reads);
    host_reset();host_fault.read_error=EIO;failed(read,name,EIO);CHECK(host_closes==1 && host_reads==1);
    host_reset();host_fault.resid=1;failed(read,name,EIO);CHECK(host_closes==1 && host_reads==1);
    host_reset();host_fault.attr_size=1;failed(read,name,EINVAL);CHECK(host_closes==1);
}
static void names_test(void) {
    static const char *const unsafe[]={NULL,"","../amss.bin","/amss.bin","amss.bin/../m3.bin","board-2.bin","amss2.bin","join.txt","qca/../hmtnv20.bin","qca//hmtnv20.bin","/qca/hmtnv20.bin","qca/hmtnv20.B31","qca/hmtnv20.b3","qca/hmtnv20.b00000","qca/hmtnv20.b3g","qca/hmtbtfw2G.tlv","qca/hmtbtfw20.tlv/","qca/hmtnv20.bin/../x"};
    for(size_t i=0;i<sizeof(unsafe)/sizeof(unsafe[0]);i++) {
        host_reset();failed(sony_wifi_firmware_read,unsafe[i],ENOENT);CHECK(!host_opens);
        host_reset();failed(sheng_bt_firmware_read,unsafe[i],ENOENT);CHECK(!host_opens);
    }
    char long_name[512];memset(long_name,'a',sizeof(long_name));long_name[511]=0;
    host_reset();failed(sony_wifi_firmware_read,long_name,ENOENT);failed(sheng_bt_firmware_read,long_name,ENOENT);CHECK(!host_opens);
    host_reset();failed(sheng_bt_firmware_read,"qca/hmtnv21.bin",ENOENT);CHECK(host_closes==0);
    uint8_t *data=NULL;size_t size=0;
    CHECK(sheng_bt_firmware_read("qca/hmtnv20.bin",NULL,&size)==EINVAL);
    CHECK(sheng_bt_firmware_read("qca/hmtnv20.bin",&data,NULL)==EINVAL);
    CHECK(sony069_wifi_verify_firmware("missing",host_files[0].data,1)==ENOENT);
    CHECK(sony069_bt_verify_firmware("qca/hmtnvff.bffff",host_files[0].data,1)==ENOENT);
}
static void gate_tests(void) {
    host_reset();native_gpu_addon_stage=0;
    CHECK(sony_wcn_wifi_inputs_ready()==EAGAIN && sony_wcn_bluetooth_inputs_ready()==EAGAIN && !host_opens);
    for(size_t i=0;i<host_file_count;i++)if(host_files[i].wifi || !strcmp(host_files[i].name,"qca/hmtbtfw20.tlv") || !strcmp(host_files[i].name,"qca/hmtnv20.bin")) {
        host_reset();host_fault.missing=host_files[i].name;
        CHECK((host_files[i].wifi?sony_wcn_wifi_inputs_ready():sony_wcn_bluetooth_inputs_ready())==ENOENT);
        CHECK(!host_live_allocations);
    }
    host_reset();CHECK(!sony_wcn_wifi_inputs_ready());CHECK(host_reads==4 && host_closes==4 && !host_live_allocations);
    host_reset();CHECK(!sony_wcn_bluetooth_inputs_ready());CHECK(host_reads==2 && host_closes==2 && !host_live_allocations);
}
int main(void) {
    host_init();files_test();reader_errors(sony_wifi_firmware_read,"amss.bin",32u*1024*1024);
    reader_errors(sheng_bt_firmware_read,"qca/hmtnv20.bin",4u*1024*1024);names_test();gate_tests();host_fini();
    printf("{\"passed\":true,\"manifest_verified\":%u,\"real_files_read\":%u,\"metadata_refused\":%u,\"failure_assertions\":%u}\n",verified,read_files,refused_metadata,assertions);
}
