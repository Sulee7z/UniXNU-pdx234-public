// SPDX-License-Identifier: MIT
// Count the accepted checkpoint once, separately from entry/refusal, per name.
// A checkpoint is not completed service startup. Missing lock acquisitions are
// reported, and a name can represent more than one launchd job.
enum {PDX_CHURN_CAP=12};
static struct pdx_churn_record {
  char name[24];unsigned enter,accepted,refused,exits,pid,ns;int status;uint64_t code;
} pdx_churn[PDX_CHURN_CAP]={
  {.name="bluetoothd"},{.name="aonsensed"},{.name="fskitd"},{.name="pfd"},
  {.name="powerdatad"},{.name="fairplayd.H2"},{.name="xpcproxy"},
  {.name="Apple.data"},{.name="LauncherControlExten"},{.name="WorldClockWidget"},
  {.name="backboardd"},{.name="SpringBoard"}
};
static unsigned pdx_churn_lock,pdx_churn_drops;
static int pdx_churn_name(const char *name) {
  if(!name)return -1;
  for(unsigned i=0;i<PDX_CHURN_CAP;++i)
    if(i==7?!strncmp(name,pdx_churn[i].name,10):
       i==8?!strncmp(name,pdx_churn[i].name,20):!strncmp(name,pdx_churn[i].name,23))return (int)i;
  return -1;
}
static void pdx_churn_exec(int pid,const char *name,const char *text) {
  const int i=pdx_churn_name(name);if(i<0)return;
  if(__atomic_exchange_n(&pdx_churn_lock,1,__ATOMIC_ACQUIRE)) {__atomic_fetch_add(&pdx_churn_drops,1,__ATOMIC_RELAXED);return;}
  struct pdx_churn_record *r=&pdx_churn[i];
  if(!strcmp(text,"exec process signature enter"))++r->enter;
  else if(!strcmp(text,"exec process signature accepted"))++r->accepted;
  else if(!strcmp(text,"exec process signature REFUSED"))++r->refused;
  r->pid=(unsigned)pid;
  __atomic_store_n(&pdx_churn_lock,0,__ATOMIC_RELEASE);
}
static void pdx_churn_exit(int pid,const char *name,int status,unsigned ns,uint64_t code) {
  const int i=pdx_churn_name(name);if(i<0)return;
  if(__atomic_exchange_n(&pdx_churn_lock,1,__ATOMIC_ACQUIRE)) {__atomic_fetch_add(&pdx_churn_drops,1,__ATOMIC_RELAXED);return;}
  struct pdx_churn_record *r=&pdx_churn[i];++r->exits;r->pid=(unsigned)pid;r->status=status;r->ns=ns;r->code=code;
  __atomic_store_n(&pdx_churn_lock,0,__ATOMIC_RELEASE);
}
static int pdx_churn_rows(unsigned now,char rows[5][48]) {
  if(__atomic_exchange_n(&pdx_churn_lock,1,__ATOMIC_ACQUIRE))return 0;
  const unsigned i=(now/16)%PDX_CHURN_CAP;const struct pdx_churn_record r=pdx_churn[i];
  const unsigned dropped=__atomic_load_n(&pdx_churn_drops,__ATOMIC_RELAXED);
  __atomic_store_n(&pdx_churn_lock,0,__ATOMIC_RELEASE);
  memset(rows,0,5*48);
  snprintf(rows[0],48,"PROC %.23s pid=%u",r.name,r.pid);
  snprintf(rows[1],48,"enter=%u accepted=%u refused=%u",r.enter,r.accepted,r.refused);
  snprintf(rows[2],48,"exits=%u rawst=%x namespace=%u",r.exits,(unsigned)r.status,r.ns);
  snprintf(rows[3],48,"code=%llx sig=%u exitcode=%u",(unsigned long long)r.code,(unsigned)r.status&127,((unsigned)r.status>>8)&255);
  snprintf(rows[4],48,"sample drops=%u; name aggregates jobs",dropped);return 1;
}
