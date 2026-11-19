/* SPDX-License-Identifier: GPL-2.0
 * K06 fixed-input real-regmap caller example, selected at build time. The
 * split operation intentionally violates the masked-update contract when
 * interleaved; regmap_update_bits is the repair. No upstream bug is claimed.
 */
#define _GNU_SOURCE
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <unistd.h>
#include "regmap-k06-cases.h"
#ifndef KCONC_CASE_INDEX
#error A fixed KCONC_CASE_INDEX is required
#endif
#ifndef KCONC_MODE
#error A fixed KCONC_MODE is required
#endif
_Static_assert(KCONC_CASE_INDEX < K06_CASE_COUNT, "case index");
_Static_assert(KCONC_MODE == KCONC_REGMAP_MODE_SPLIT || KCONC_MODE == KCONC_REGMAP_MODE_UPDATE_BITS, "mode");
#define MAX_FDS 4096
static const struct k06_case *input=&k06_cases[KCONC_CASE_INDEX];
static int device_fd=-1, initial_fds[MAX_FDS];
static size_t initial_count;
static unsigned int epoch,calls[2],tids[2];
static int op_rc[2],op_errno[2];
static struct kconc_regmap_op operations[2];

static int compare_fd(const void *a,const void *b) {
  int left=*(const int *)a,right=*(const int *)b;
  return (left>right)-(left<right);
}
static bool collect_fds(int *fds,size_t *count) {
  DIR *dir=opendir("/proc/self/fd");
  if (!dir) return false;
  int own=dirfd(dir); *count=0; errno=0;
  struct dirent *entry;
  while ((entry=readdir(dir))!=NULL) {
    char *end=NULL; long value=strtol(entry->d_name,&end,10);
    if (!*entry->d_name || *end || value<0 || value>INT_MAX || value==own) continue;
    if (*count==MAX_FDS) { closedir(dir); return false; }
    fds[(*count)++]=(int)value;
  }
  int read_error=errno;
  if (closedir(dir) || read_error) return false;
  qsort(fds,*count,sizeof(*fds),compare_fd); return true;
}
static bool same_fds(const int *a,size_t na,const int *b,size_t nb) {
  return na==nb && !memcmp(a,b,na*sizeof(*a));
}
static void fds_json(const int *fds,size_t count) {
  putchar('['); for (size_t i=0;i<count;++i) printf("%s%d",i?",":"",fds[i]); putchar(']');
}
static void phase_end(void) { puts("}"); if (fflush(stdout)) _exit(74); }
static bool teardown(void) {
  struct kconc_regmap_status status={.abi=KCONC_REGMAP_ABI};
  int rc=device_fd>=0?ioctl(device_fd,KCONC_REGMAP_TEARDOWN,&status):-1;
  int saved_errno=rc<0?errno:0;
  bool empty=rc==0 && k06_empty(&status);
  int close_rc=device_fd>=0?close(device_fd):0; device_fd=-1;
  int actual[MAX_FDS]; size_t count=0; bool observed=collect_fds(actual,&count);
  bool restored=observed && same_fds(initial_fds,initial_count,actual,count);
  bool passed=empty && close_rc==0 && restored;
  printf("KCONC_PHASE {\"phase\":\"teardown\",\"passed\":%s,\"ioctl_rc\":%d,\"errno\":%d,"
    "\"map_empty\":%s,\"resources_closed\":%s,\"context_state\":%u,\"active\":%u,\"completed_mask\":%u,"
    "\"snapshot_valid\":%u,\"values\":",k06_bool(passed),rc,saved_errno,k06_bool(empty),k06_bool(close_rc==0),
    status.state,status.active,status.completed_mask,status.snapshot_valid);
  k06_values_json(status.values);
  printf(",\"roles_zero\":%s,\"fd_set_restored\":%s,\"fd_snapshot_observed\":%s,\"expected_fds\":",
    k06_bool(k06_roles_zero(&status)),k06_bool(restored),k06_bool(observed));
  fds_json(initial_fds,initial_count); printf(",\"actual_fds\":"); fds_json(actual,count); phase_end();
  return passed;
}
void test_setup(void) {
  memset(calls,0,sizeof(calls)); memset(tids,0,sizeof(tids)); memset(operations,0,sizeof(operations));
  op_rc[0]=op_rc[1]=-1; op_errno[0]=op_errno[1]=0;
  bool observed=collect_fds(initial_fds,&initial_count);
  if (observed) device_fd=open(KCONC_REGMAP_DEVICE,O_RDWR|O_CLOEXEC);
  struct kconc_regmap_reset reset={.abi=KCONC_REGMAP_ABI};
  memcpy(reset.initial,input->initial,sizeof(reset.initial));
  int rc=device_fd>=0?ioctl(device_fd,KCONC_REGMAP_RESET,&reset):-1,saved_errno=rc<0?errno:0;
  epoch=reset.epoch;
  bool setup_ok=observed && device_fd>=0 && rc==0 && epoch;
  printf("KCONC_PHASE {\"phase\":\"setup\",\"passed\":%s,\"fault\":\"none\",\"injected\":false,"
    "\"fd\":%d,\"reset_rc\":%d,\"errno\":%d,\"epoch\":%u,\"mode\":\"%s\",",
    k06_bool(setup_ok),device_fd,rc,saved_errno,epoch,k06_mode_name(KCONC_MODE));
  k06_inputs_json(input); printf(",\"initial_fds\":"); fds_json(initial_fds,initial_count); phase_end();
  if (!setup_ok) { (void)teardown(); _exit(71); }
  struct kconc_regmap_status status={.abi=KCONC_REGMAP_ABI};
  rc=ioctl(device_fd,KCONC_REGMAP_STATUS,&status);
  int actual[MAX_FDS],expected[MAX_FDS]; size_t count=0,expected_count=initial_count;
  observed=collect_fds(actual,&count); memcpy(expected,initial_fds,initial_count*sizeof(*expected));
  bool room=initial_count<MAX_FDS;
  if (room) { expected[expected_count++]=device_fd; qsort(expected,expected_count,sizeof(*expected),compare_fd); }
  bool matches=room && observed && same_fds(expected,expected_count,actual,count);
  bool ready=rc==0 && k06_ready(&status,epoch,input->initial),passed=ready && matches;
  printf("KCONC_PHASE {\"phase\":\"initial_state\",\"passed\":%s,\"epoch\":%u,\"regmap_ready\":%s,\"values\":",
    k06_bool(passed),status.epoch,k06_bool(ready)); k06_values_json(status.values);
  printf(",\"active\":%u,\"completed_mask\":%u,\"fd_set_matches\":%s,\"snapshot_valid\":%u,"
    "\"context_state\":%u,\"roles_zero\":%s,\"status_rc\":%d",status.active,status.completed_mask,
    k06_bool(matches),status.snapshot_valid,status.state,k06_bool(k06_roles_zero(&status)),rc); phase_end();
  if (!passed) { (void)teardown(); _exit(72); }
}
static void run_operation(unsigned int role) {
  ++calls[role]; tids[role]=(unsigned int)syscall(SYS_gettid);
  const struct k06_input *op=&input->operations[role];
  operations[role]=(struct kconc_regmap_op){.abi=KCONC_REGMAP_ABI,.epoch=epoch,.role=role,
    .reg=op->reg,.mask=op->mask,.value=op->value,.mode=KCONC_MODE};
  op_rc[role]=ioctl(device_fd,KCONC_REGMAP_OP,&operations[role]);
  op_errno[role]=op_rc[role]<0?errno:0;
}
void test_thread1(void) { run_operation(0); }
void test_thread2(void) { run_operation(1); }
void test_end(void) {
  bool valid=calls[0]==1 && calls[1]==1;
  printf("KCONC_PHASE {\"phase\":\"operations\",\"a_calls\":%u,\"b_calls\":%u,\"results\":[",calls[0],calls[1]);
  for (unsigned int role=0;role<2;++role) {
    valid &= k06_op_valid(&operations[role],input,role,KCONC_MODE,epoch,tids[role],op_rc[role],op_errno[role]);
    if (role) putchar(',');
    k06_op_json(&operations[role],op_rc[role],op_errno[role],tids[role]);
  }
  printf("],\"passed\":%s",k06_bool(valid)); phase_end();
  struct kconc_regmap_status status={.abi=KCONC_REGMAP_ABI};
  int rc=ioctl(device_fd,KCONC_REGMAP_STATUS,&status);
  valid &= rc==0 && status.abi==KCONC_REGMAP_ABI && status.state==KCONC_REGMAP_READY &&
    status.snapshot_valid==1 && !status.active && status.epoch==epoch && status.completed_mask==3;
  for (unsigned int role=0;role<2;++role) valid &= k06_slot_matches(&status.roles[role],&operations[role]);
  bool allowed=k06_allowed(input,status.values);
  printf("KCONC_PHASE {\"phase\":\"property\",\"passed\":%s,\"infrastructure_valid\":%s,"
    "\"oracle\":\"regmap-two-masked-updates\",\"allowed\":%s,\"natural_passed\":%s,\"injected\":false,"
    "\"kernel_bug_claim\":false,\"caller_misuse_example\":true,\"status_rc\":%d,\"epoch\":%u,\"values\":",
    k06_bool(valid),k06_bool(valid),k06_bool(allowed),k06_bool(allowed),rc,status.epoch);
  k06_values_json(status.values);
  printf(",\"snapshot_valid\":%u,\"context_state\":%u,\"active\":%u,\"completed_mask\":%u,\"roles\":[",
    status.snapshot_valid,status.state,status.active,status.completed_mask);
  k06_role_json(&status.roles[0]); putchar(','); k06_role_json(&status.roles[1]); printf("]"); phase_end();
  bool cleaned=teardown();
  /* A detected property violation is evidence, not an executor failure. */
  if (!cleaned || !valid) _exit(73);
}
