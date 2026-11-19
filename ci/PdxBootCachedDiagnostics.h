// SPDX-License-Identifier: MIT
// Called under render_busy, only on the bound diagnostic page. No MMIO,
// allocation, selector invocation or polling. Strings are best-effort samples.
extern unsigned native_legacy_state_words(char *,unsigned) __attribute__((weak_import));
extern unsigned native_legacy_clients_dump(char *,unsigned) __attribute__((weak_import));
enum {PDX_CACHED_ROWS=64, PDX_CACHED_COLS=47};
static char pdx_cached_drawn[PDX_CACHED_ROWS][PDX_CACHED_COLS+1];
static unsigned pdx_cached_valid[PDX_CACHED_ROWS],pdx_cached_second,pdx_cached_sampled;
static char pdx_cached_state[128],pdx_cached_clients[128];
#ifdef PDX_FIRST_FRAME_DIAGNOSTICS_H
static char pdx_cached_first_frame[PDX_FIRST_FRAME_ROWS][PDX_FIRST_FRAME_COLS];
static int pdx_cached_first_frame_on=-1;
#endif
static void pdx_cached_invalidate(void) {
  memset(pdx_cached_valid,0,sizeof(pdx_cached_valid));
}
static void pdx_cached_row(unsigned row,unsigned x0,unsigned cols,const char *text,uint32_t color) {
  char piece[PDX_CACHED_COLS+1];
  if(row>=PDX_CACHED_ROWS)return;
  unsigned n=0;while(n<cols && text[n]){piece[n]=text[n];++n;}piece[n]=0;
  if(pdx_cached_valid[row] && !strcmp(piece,pdx_cached_drawn[row]))return;
  unsigned top=(13+row)*14*display.scale;
  for(unsigned x=0;x<cols;++x) {
    unsigned c=x<n?(unsigned char)piece[x]:' ';if(c<32||c>126)c='?';
    uint64_t glyph=font[c-32];
    for(unsigned y=0;y<14;++y) {
      unsigned bits=y<6?(unsigned)(glyph>>(32+y*5)):y<12?(unsigned)(glyph>>((y-6)*5)):0;
      for(unsigned dx=0;dx<6;++dx)
        for(unsigned sy=0;sy<display.scale;++sy)
          for(unsigned sx=0;sx<display.scale;++sx) {
            if(__atomic_load_n(&display.yield_requested,__ATOMIC_ACQUIRE))return;
            *(volatile uint32_t *)(display.frame+(uintptr_t)(top+y*display.scale+sy)*display.stride+
              (x0+(x*6+dx)*display.scale+sx)*4)=dx<5&&((bits>>dx)&1)?color:0;
          }
    }
  }
  memcpy(pdx_cached_drawn[row],piece,n+1);pdx_cached_valid[row]=1;
}
static unsigned pdx_cached_wrap(unsigned row,unsigned x0,unsigned cols,const char *text,unsigned cap,uint32_t color) {
  // Fixed rows per source erase shrinking/empty tails. Bound every source read;
  // every byte through cap-2 remains visible, including PUB's failure suffix.
  unsigned length=0;while(length+1<cap && text[length])++length;
  for(unsigned at=0;at<cap-1;at+=cols) {
    char piece[PDX_CACHED_COLS+1];unsigned n=0;
    while(n<cols && at+n<length){char c=text[at+n];piece[n++]=c=='\n'?' ':c;}
    piece[n]=0;pdx_cached_row(row++,x0,cols,piece,color);
  }
  return row;
}
static void ext_overlay_locked(void) {
  if(!display.bound || !display.frame || !display.scale ||
     __atomic_load_n(&display.yield_requested,__ATOMIC_ACQUIRE)) {
    pdx_cached_invalidate();return;
  }
  unsigned cell=6*display.scale,x0=BP_COLS*cell+8;
  if(display.width<=x0+8 || display.stride<display.width*4)return;
  unsigned cols=(display.width-x0-8)/cell;if(cols>PDX_CACHED_COLS)cols=PDX_CACHED_COLS;
  if(!cols)return;
  unsigned needed=8+2*((111+cols-1)/cols)+2*((127+cols-1)/cols);
#ifdef PDX_FIRST_FRAME_DIAGNOSTICS_H
  if(pdx_cached_first_frame_on<0) {
    unsigned value=0;PE_parse_boot_argn("first-frame-diag",&value,sizeof value);pdx_cached_first_frame_on=value==1;
  }
  if(pdx_cached_first_frame_on)needed+=PDX_FIRST_FRAME_ROWS*((47+cols-1)/cols);
#endif
  // Fit the whole panel before drawing any of it; no truncated failure suffix.
  if(needed>PDX_CACHED_ROWS || (13+needed)*14*display.scale>display.height)return;
  ext_data_rows();
  unsigned now=seconds();
  if(!pdx_cached_sampled || now!=pdx_cached_second) {
    pdx_cached_sampled=1;pdx_cached_second=now;
    memcpy(pdx_cached_state,"D27 state unavailable",sizeof("D27 state unavailable"));
    memcpy(pdx_cached_clients,"opens unavailable",sizeof("opens unavailable"));
    if(native_legacy_state_words) {
      (void)native_legacy_state_words(pdx_cached_state,sizeof(pdx_cached_state));
      if(!pdx_cached_state[0])memcpy(pdx_cached_state,"D27 state unavailable",sizeof("D27 state unavailable"));
    }
    // display009's header is >=70 bytes, so its at+120<cap detail-loop
    // condition cannot hold for this 128-byte buffer, even with zero counts.
    if(native_legacy_clients_dump)(void)native_legacy_clients_dump(pdx_cached_clients,sizeof(pdx_cached_clients));
    pdx_cached_state[127]=pdx_cached_clients[127]=0;
#ifdef PDX_FIRST_FRAME_DIAGNOSTICS_H
    if(pdx_cached_first_frame_on)pdx_first_frame_snapshot(now,pdx_cached_first_frame);
#endif
  }
  for(unsigned slot=0;slot<8;++slot) {
    char text[48];memcpy(text,boot_progress_ext[slot],47);text[47]=0;
    pdx_cached_row(slot,x0,cols,text,slot<4?0xff80ffff:0xffffa0ff);
  }
  unsigned row=8;
  for(unsigned slot=0;slot<2;++slot) {
    char text[112];memcpy(text,boot_progress_ext_wide[slot],111);text[111]=0;
    row=pdx_cached_wrap(row,x0,cols,text,sizeof(text),0xffffa0ff);
  }
  row=pdx_cached_wrap(row,x0,cols,pdx_cached_state,sizeof(pdx_cached_state),0xffffff00);
  row=pdx_cached_wrap(row,x0,cols,pdx_cached_clients,sizeof(pdx_cached_clients),0xffffff00);
#ifdef PDX_FIRST_FRAME_DIAGNOSTICS_H
  if(pdx_cached_first_frame_on)for(unsigned i=0;i<PDX_FIRST_FRAME_ROWS;++i)
    row=pdx_cached_wrap(row,x0,cols,pdx_cached_first_frame[i],PDX_FIRST_FRAME_COLS,0xffaaffff);
#endif
}
