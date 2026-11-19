// SPDX-License-Identifier: MIT
// Exact D27 ControlAction fatal-error evidence. Only the ordinary exit collector
// calls the user reader. The exported text accessor copies an owned RAM report.
#ifndef PDX_SWIFT_TRAP_DIAGNOSTIC_H
#define PDX_SWIFT_TRAP_DIAGNOSTIC_H
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#if !defined(KERNEL)
#include <stdio.h>
#endif

enum {PDX_SWIFT_MESSAGE_BYTES=768,PDX_SWIFT_REPORT_BYTES=1536,PDX_SWIFT_MAX_BYTES=65536,
      PDX_SWIFT_PAGE_ROWS=8,PDX_SWIFT_PAGE_COLS=47};
#define PDX_SWIFT_TRAP_PC UINT64_C(0x181edaf54)
#define PDX_SWIFT_CALLER_PC UINT64_C(0x18bd74b14)
#define PDX_SWIFT_TRAP_ESR UINT64_C(0xf2000001)
enum pdx_swift_status {
  PDX_SWIFT_UNRELATED=0,PDX_SWIFT_OK,PDX_SWIFT_UNAVAILABLE_CORRELATION,
  PDX_SWIFT_UNAVAILABLE_CONTEXT,PDX_SWIFT_READER_UNAVAILABLE,PDX_SWIFT_ADDRESS,
  PDX_SWIFT_COPY_INSTRUCTION,PDX_SWIFT_INSTRUCTION,PDX_SWIFT_FRAME,
  PDX_SWIFT_COPY_FRAME,PDX_SWIFT_CALLER,PDX_SWIFT_COPY_CALLER,
  PDX_SWIFT_ARGUMENTS,PDX_SWIFT_COPY_STRING,PDX_SWIFT_ERROR,
  PDX_SWIFT_LAYOUT,PDX_SWIFT_LENGTH,PDX_SWIFT_COPY_HEAD,
  PDX_SWIFT_PREFIX,PDX_SWIFT_COPY_TAIL
};
struct pdx_swift_snapshot {
  unsigned valid,signal,ordinary_exit;
  int pid,exit_pid,current_pid;
  uint64_t thread_id,current_thread_id,pc,sp,fp,esr,slide,x20,x21,user_limit;
};
typedef int (*pdx_swift_read)(void *,uint64_t,void *,size_t);
// The kernel adapter uses ptrauth_strip(..., ptrauth_key_return_address).
// No guessed address-width/PAC mask is applied by the portable collector.
typedef uint64_t (*pdx_swift_strip_return)(void *,uint64_t);
struct pdx_swift_reader {void *context;pdx_swift_read read;pdx_swift_strip_return strip_return;};
struct pdx_swift_result {
  enum pdx_swift_status status;
  int pid,copy_error;
  uint32_t instruction;
  unsigned head_bytes,tail_bytes;
  uint64_t thread_id,current_thread_id,copy_address,caller_fp,caller_return,parent_return;
  uint64_t word0,word1,error_object,total_bytes,tail_offset;
  unsigned char message[PDX_SWIFT_MESSAGE_BYTES+1];
};
static const char *pdx_swift_status_name(enum pdx_swift_status value) {
  switch(value) {
    case PDX_SWIFT_OK:return "captured";
    case PDX_SWIFT_UNAVAILABLE_CORRELATION:return "unavailable-pid-thread";
    case PDX_SWIFT_UNAVAILABLE_CONTEXT:return "unavailable-exit-context";
    case PDX_SWIFT_READER_UNAVAILABLE:return "reader-unavailable";
    case PDX_SWIFT_ADDRESS:return "address-range";
    case PDX_SWIFT_COPY_INSTRUCTION:return "copy-instruction";
    case PDX_SWIFT_INSTRUCTION:return "instruction-mismatch";
    case PDX_SWIFT_FRAME:return "frame-mismatch";
    case PDX_SWIFT_COPY_FRAME:return "copy-frame";
    case PDX_SWIFT_CALLER:return "caller-mismatch";
    case PDX_SWIFT_COPY_CALLER:return "copy-caller";
    case PDX_SWIFT_ARGUMENTS:return "argument-mismatch";
    case PDX_SWIFT_COPY_STRING:return "copy-string";
    case PDX_SWIFT_ERROR:return "error-object-mismatch";
    case PDX_SWIFT_LAYOUT:return "unsupported-string-layout";
    case PDX_SWIFT_LENGTH:return "string-length";
    case PDX_SWIFT_COPY_HEAD:return "copy-message-head";
    case PDX_SWIFT_PREFIX:return "message-prefix-mismatch";
    case PDX_SWIFT_COPY_TAIL:return "copy-message-tail";
    default:return "unrelated";
  }
}
static int pdx_swift_range(uint64_t address,size_t bytes,uint64_t limit) {
  return address && address<limit && (uint64_t)bytes<=limit-address;
}
static int pdx_swift_read_at(const struct pdx_swift_snapshot *snapshot,const struct pdx_swift_reader *reader,
    struct pdx_swift_result *result,uint64_t address,void *out,size_t bytes,enum pdx_swift_status failure) {
  result->copy_address=address;
  if(!pdx_swift_range(address,bytes,snapshot->user_limit)){result->status=PDX_SWIFT_ADDRESS;return 0;}
  result->copy_error=reader->read(reader->context,address,out,bytes);
  if(result->copy_error){result->status=failure;return 0;}
  return 1;
}
// Return 0 for an unrelated site; return 1 with an explicit status for a matching
// PC/ESR, including unavailable correlation, unsupported layout and copy failure.
static int pdx_swift_trap_collect(const struct pdx_swift_snapshot *s,const struct pdx_swift_reader *reader,
    struct pdx_swift_result *r) {
  static const char prefix[]="Can't create CHSIntentReference from ";
  uint64_t frame[4]={0},caller[2]={0},words[3]={0};
  if(!r)return 0;
  memset(r,0,sizeof(*r));
  if(!s || !s->valid || s->signal!=5 || s->esr!=PDX_SWIFT_TRAP_ESR ||
     s->pc<s->slide || s->pc-s->slide!=PDX_SWIFT_TRAP_PC)return 0;
  r->pid=s->pid;r->thread_id=s->thread_id;r->current_thread_id=s->current_thread_id;
  if(s->pid<=0 || s->pid!=s->exit_pid || s->pid!=s->current_pid || !s->thread_id ||
     s->thread_id!=s->current_thread_id){r->status=PDX_SWIFT_UNAVAILABLE_CORRELATION;return 1;}
  if(!s->ordinary_exit){r->status=PDX_SWIFT_UNAVAILABLE_CONTEXT;return 1;}
  if(!reader || !reader->read || !reader->strip_return){r->status=PDX_SWIFT_READER_UNAVAILABLE;return 1;}
  if(!pdx_swift_read_at(s,reader,r,s->pc,&r->instruction,4,PDX_SWIFT_COPY_INSTRUCTION))return 1;
  if(r->instruction!=UINT32_C(0xd4200020)){r->status=PDX_SWIFT_INSTRUCTION;return 1;}
  if(!s->sp || (s->sp&15) || (s->fp&15) || s->sp>UINT64_MAX-0x20 || s->fp!=s->sp+0x20) {
    r->status=PDX_SWIFT_FRAME;return 1;
  }
  if(!pdx_swift_read_at(s,reader,r,s->fp,frame,sizeof(frame),PDX_SWIFT_COPY_FRAME))return 1;
  r->caller_fp=frame[0];r->caller_return=reader->strip_return(reader->context,frame[1]);
  if(!r->caller_fp || (r->caller_fp&15) || r->caller_fp<=s->fp ||
     r->caller_fp-s->fp<0x90 || r->caller_fp-s->fp>UINT64_C(1048576) ||
     r->caller_return<s->slide || r->caller_return-s->slide!=PDX_SWIFT_CALLER_PC) {
    r->status=PDX_SWIFT_CALLER;return 1;
  }
  if(frame[2]!=58 || (uint32_t)frame[3]!=0 || s->x20!=r->caller_fp-0x68) {
    r->status=PDX_SWIFT_ARGUMENTS;return 1;
  }
  if(!pdx_swift_read_at(s,reader,r,r->caller_fp,caller,sizeof(caller),PDX_SWIFT_COPY_CALLER))return 1;
  r->parent_return=reader->strip_return(reader->context,caller[1]);
  if(!pdx_swift_read_at(s,reader,r,r->caller_fp-0x70,words,sizeof(words),PDX_SWIFT_COPY_STRING))return 1;
  r->error_object=words[0];r->word0=words[1];r->word1=words[2];
  if(!words[0] || words[0]!=s->x21){r->status=PDX_SWIFT_ERROR;return 1;}
  // D27's native tail-allocated String UTF8 is at the discriminator-free address
  // +32. Small, foreign and shared representations are deliberately unsupported.
  if((r->word1&UINT64_C(0x3000000000000000)) || !(r->word0&UINT64_C(0x1000000000000000))) {
    r->status=PDX_SWIFT_LAYOUT;return 1;
  }
  r->total_bytes=r->word0&UINT64_C(0x0000ffffffffffff);
  if(r->total_bytes<sizeof(prefix)-1 || r->total_bytes>PDX_SWIFT_MAX_BYTES) {
    r->status=PDX_SWIFT_LENGTH;return 1;
  }
  uint64_t address=r->word1&UINT64_C(0x0fffffffffffffff);
  if(address>UINT64_MAX-32){r->status=PDX_SWIFT_ADDRESS;return 1;}
  address+=32;
  // Validate the whole declared extent, though at most 768 bytes are read.
  if(!pdx_swift_range(address,(size_t)r->total_bytes,s->user_limit)) {
    r->status=PDX_SWIFT_ADDRESS;r->copy_address=address;return 1;
  }
  unsigned head=r->total_bytes<=PDX_SWIFT_MESSAGE_BYTES?(unsigned)r->total_bytes:256;
  unsigned tail=r->total_bytes<=PDX_SWIFT_MESSAGE_BYTES?0:512;
  if(!pdx_swift_read_at(s,reader,r,address,r->message,head,PDX_SWIFT_COPY_HEAD)) {
    memset(r->message,0,sizeof(r->message));return 1;
  }
  if(memcmp(r->message,prefix,sizeof(prefix)-1)) {
    memset(r->message,0,sizeof(r->message));r->status=PDX_SWIFT_PREFIX;return 1;
  }
  r->tail_offset=tail?r->total_bytes-tail:0;
  if(tail && !pdx_swift_read_at(s,reader,r,address+r->tail_offset,r->message+head,tail,PDX_SWIFT_COPY_TAIL)) {
    memset(r->message,0,sizeof(r->message));return 1;
  }
  r->head_bytes=head;r->tail_bytes=tail;r->message[head+tail]=0;
  r->status=PDX_SWIFT_OK;return 1;
}
static unsigned pdx_swift_put(char *out,unsigned capacity,unsigned used,const char *text,unsigned count) {
  if(!out || !capacity)return 0;
  if(used>=capacity)used=capacity-1;
  for(unsigned i=0;i<count && used+1<capacity;++i)out[used++]=text[i];
  out[used]=0;return used;
}
static unsigned pdx_swift_print_bytes(char *out,unsigned capacity,unsigned used,const unsigned char *bytes,unsigned count) {
  if(count>PDX_SWIFT_MESSAGE_BYTES)count=PDX_SWIFT_MESSAGE_BYTES;
  for(unsigned i=0;i<count && used+1<capacity;++i) {
    char c=bytes[i]>=32 && bytes[i]<=126?(char)bytes[i]:'?';
    used=pdx_swift_put(out,capacity,used,&c,1);
  }
  return used;
}
static unsigned pdx_swift_trap_format(const struct pdx_swift_result *r,char *out,unsigned capacity) {
  if(!out || !capacity)return 0;
  out[0]=0;if(!r || r->status==PDX_SWIFT_UNRELATED)return 0;
  int length=snprintf(out,capacity,
    "SWIFT pid=%d tid=%llx current=%llx status=%s copy=%d at=%llx\n"
    "raw=%016llx/%016llx bytes=%llu head=%u tail=%u tail_at=%llu\n"
    "site=181edaf54 caller=%llx fp=%llx error=%llx\n",
    r->pid,(unsigned long long)r->thread_id,(unsigned long long)r->current_thread_id,
    pdx_swift_status_name(r->status),r->copy_error,(unsigned long long)r->copy_address,
    (unsigned long long)r->word0,(unsigned long long)r->word1,(unsigned long long)r->total_bytes,
    r->head_bytes,r->tail_bytes,(unsigned long long)r->tail_offset,(unsigned long long)r->caller_return,
    (unsigned long long)r->caller_fp,(unsigned long long)r->error_object);
  if(length<0){out[0]=0;return 0;}
  unsigned used=(unsigned)length<capacity?(unsigned)length:capacity-1;
  if(r->status!=PDX_SWIFT_OK || r->head_bytes>PDX_SWIFT_MESSAGE_BYTES ||
     r->tail_bytes>PDX_SWIFT_MESSAGE_BYTES-r->head_bytes)return used;
  used=pdx_swift_put(out,capacity,used,r->tail_bytes?"MSG head: ":"MSG: ",r->tail_bytes?10:5);
  used=pdx_swift_print_bytes(out,capacity,used,r->message,r->head_bytes);
  if(r->tail_bytes) {
    used=pdx_swift_put(out,capacity,used,"\nMSG tail: ",11);
    used=pdx_swift_print_bytes(out,capacity,used,r->message+r->head_bytes,r->tail_bytes);
  }
  return used;
}
static unsigned pdx_swift_cache_lock,pdx_swift_cache_length,pdx_swift_cache_dropped;
static char pdx_swift_cached_report[PDX_SWIFT_REPORT_BYTES];
// Keep the original copied bytes as well as the printable view. Display
// sanitization must not destroy the retained UTF8/error evidence.
static volatile struct pdx_swift_result pdx_swift_cached_result;
static int pdx_swift_trap_publish(const struct pdx_swift_result *result) {
  char text[PDX_SWIFT_REPORT_BYTES];
  unsigned length=pdx_swift_trap_format(result,text,sizeof(text));
  if(!length)return 0;
  if(__atomic_exchange_n(&pdx_swift_cache_lock,1,__ATOMIC_ACQUIRE)) {
    __atomic_fetch_add(&pdx_swift_cache_dropped,1,__ATOMIC_RELAXED);return 0;
  }
  memcpy(pdx_swift_cached_report,text,length+1);pdx_swift_cache_length=length;
  pdx_swift_cached_result=*result;
  __atomic_store_n(&pdx_swift_cache_lock,0,__ATOMIC_RELEASE);return 1;
}
// Returns bytes copied, excluding NUL; 0 means no report/contended/empty capacity.
// This accessor never invokes a reader, touches the process map or formats text.
unsigned pdx_swift_trap_text(char *out,unsigned capacity) {
  if(!out || !capacity)return 0;
  out[0]=0;
  if(__atomic_exchange_n(&pdx_swift_cache_lock,1,__ATOMIC_ACQUIRE))return 0;
  unsigned length=pdx_swift_cache_length;
  if(length>=capacity)length=capacity-1;
  if(length)memcpy(out,pdx_swift_cached_report,length);
  out[length]=0;
  __atomic_store_n(&pdx_swift_cache_lock,0,__ATOMIC_RELEASE);return length;
}
#endif
