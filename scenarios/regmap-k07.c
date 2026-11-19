/* SPDX-License-Identifier: GPL-2.0
 * A nonblocking compound regmap operation with correct or incorrect gate
 * selection. Critical-region overlap, not a lost register bit, is the bug.
 */
#define _GNU_SOURCE
#include <dirent.h>
#include <fcntl.h>
#include <limits.h>
#include <stdlib.h>
#include "regmap-k07-cases.h"
#ifndef KCONC_CASE_INDEX
#error A fixed KCONC_CASE_INDEX is required
#endif
#ifndef KCONC_MODE
#error A fixed KCONC_MODE is required
#endif
_Static_assert(KCONC_CASE_INDEX<K07_CASE_COUNT,"case index");
_Static_assert(KCONC_MODE==KCONC_REGMAP_MODE_SHARED || KCONC_MODE==KCONC_REGMAP_MODE_PER_ROLE,"mode");
#define MAX_FDS 4096
static const struct k07_case *input=&k07_cases[KCONC_CASE_INDEX];
static int device_fd=-1,initial_fds[MAX_FDS];static size_t initial_count;
static unsigned int epoch,calls[2],tids[2];static int op_rc[2],op_errno[2];
static struct kconc_regmap_op operations[2];
static int compare_fd(const void *a,const void *b) {
  int left=*(const int *)a,right=*(const int *)b;return (left>right)-(left<right);
}
static bool collect_fds(int *fds,size_t *count) {
  DIR *dir=opendir("/proc/self/fd");if (!dir) return false;
  int own=dirfd(dir);*count=0;errno=0;struct dirent *entry;
  while ((entry=readdir(dir))!=NULL) {
    char *end=NULL;long value=strtol(entry->d_name,&end,10);
    if (!*entry->d_name || *end || value<0 || value>INT_MAX || value==own) continue;
    if (*count==MAX_FDS) { closedir(dir);return false; }fds[(*count)++]=(int)value;
  }
  int read_error=errno;if (closedir(dir) || read_error) return false;
  qsort(fds,*count,sizeof(*fds),compare_fd);return true;
}
static void fds_json(const int *fds,size_t count) {
  putchar('[');for (size_t i=0;i<count;++i) printf("%s%d",i?",":"",fds[i]);putchar(']');
}
static bool same_fds(const int *a,size_t na,const int *b,size_t nb) { return na==nb && !memcmp(a,b,na*sizeof(*a)); }
static void phase_end(void) { puts("}");if (fflush(stdout)) _exit(74); }
static bool teardown(bool progress) {
  unsigned int current_epoch=epoch;bool progressed=false;
  printf("KCONC_PHASE {\"phase\":\"teardown\",\"post_control_progress\":");
  if (progress) progressed=k07_sequential_json(device_fd,input,KCONC_MODE,1,epoch+1,0,&current_epoch);
  else printf("null");
  struct kconc_regmap_status empty={.abi=KCONC_REGMAP_ABI};
  int rc=device_fd>=0?ioctl(device_fd,KCONC_REGMAP_TEARDOWN,&empty):-1,err=rc<0?errno:0;
  bool map_empty=rc==0 && !err && k07_empty(&empty,current_epoch);
  int close_rc=device_fd>=0?close(device_fd):0;device_fd=-1;
  int actual[MAX_FDS];size_t count=0;bool observed=collect_fds(actual,&count);
  bool restored=observed && same_fds(initial_fds,initial_count,actual,count);
  bool passed=map_empty && !close_rc && restored && (!progress || progressed);
  printf(",\"passed\":%s,\"ioctl_rc\":%d,\"errno\":%d,\"close_rc\":%d,\"map_empty\":%s,\"empty\":",
    k07_bool(passed),rc,err,close_rc,k07_bool(map_empty));k07_status_json(&empty);
  printf(",\"resources_closed\":%s,\"fd_set_restored\":%s,\"fd_snapshot_observed\":%s,\"expected_fds\":",
    k07_bool(close_rc==0),k07_bool(restored),k07_bool(observed));fds_json(initial_fds,initial_count);
  printf(",\"actual_fds\":");fds_json(actual,count);phase_end();return passed;
}
void test_setup(void) {
  memset(calls,0,sizeof(calls));memset(tids,0,sizeof(tids));memset(operations,0,sizeof(operations));
  op_rc[0]=op_rc[1]=-1;op_errno[0]=op_errno[1]=0;
  bool observed=collect_fds(initial_fds,&initial_count);
  if (observed) device_fd=open(KCONC_REGMAP_DEVICE,O_RDWR|O_CLOEXEC);
  struct kconc_regmap_reset reset={.abi=KCONC_REGMAP_ABI};memcpy(reset.initial,input->initial,sizeof(reset.initial));
  int rc=device_fd>=0?ioctl(device_fd,KCONC_REGMAP_RESET,&reset):-1,err=rc<0?errno:0;epoch=reset.epoch;
  bool setup_ok=observed && device_fd>=0 && rc==0 && epoch;
  printf("KCONC_PHASE {\"phase\":\"setup\",\"passed\":%s,\"fault\":\"none\",\"injected\":false,\"fd\":%d,"
    "\"reset_rc\":%d,\"errno\":%d,\"epoch\":%u,\"mode\":\"%s\",",k07_bool(setup_ok),device_fd,rc,err,epoch,k07_mode(KCONC_MODE));
  k07_inputs_json(input);printf(",\"reset\":");k07_reset_json(&reset);printf(",\"initial_fds\":");fds_json(initial_fds,initial_count);phase_end();
  if (!setup_ok) { (void)teardown(false);_exit(71); }
  struct kconc_regmap_status initial;rc=k07_get_status(device_fd,&initial);
  int actual[MAX_FDS],expected[MAX_FDS];size_t count=0,expected_count=initial_count;
  observed=collect_fds(actual,&count);memcpy(expected,initial_fds,initial_count*sizeof(*expected));
  bool room=initial_count<MAX_FDS;
  if (room) { expected[expected_count++]=device_fd;qsort(expected,expected_count,sizeof(*expected),compare_fd); }
  bool matches=room && observed && same_fds(expected,expected_count,actual,count);
  bool passed=rc==0 && k07_ready(&initial,epoch,input->initial) && matches;
  printf("KCONC_PHASE {\"phase\":\"initial_state\",\"passed\":%s,\"status_rc\":%d,\"initial\":",k07_bool(passed),rc);
  k07_status_json(&initial);printf(",\"fd_set_matches\":%s,\"expected_fds\":",k07_bool(matches));fds_json(expected,expected_count);
  printf(",\"actual_fds\":");fds_json(actual,count);phase_end();
  if (!passed) { (void)teardown(false);_exit(72); }
}
static void run_operation(unsigned int role) {
  ++calls[role];tids[role]=(unsigned int)syscall(SYS_gettid);const struct k07_input *in=&input->operations[role];
  operations[role]=(struct kconc_regmap_op){.abi=KCONC_REGMAP_ABI,.epoch=epoch,.role=role,.reg=in->reg,.mask=in->mask,.value=in->value,.mode=KCONC_MODE};
  op_rc[role]=ioctl(device_fd,KCONC_REGMAP_OP,&operations[role]);op_errno[role]=op_rc[role]<0?errno:0;
}
void test_thread1(void) { run_operation(0); }
void test_thread2(void) { run_operation(1); }
void test_end(void) {
  bool valid=calls[0]==1 && calls[1]==1;
  printf("KCONC_PHASE {\"phase\":\"operations\",\"a_calls\":%u,\"b_calls\":%u,\"results\":[",calls[0],calls[1]);
  for (unsigned int role=0;role<2;++role) {
    valid &= k07_op_valid(&operations[role],input,role,KCONC_MODE,epoch,tids[role],op_rc[role],op_errno[role]);
    if (role) putchar(',');
    k07_op_json(&operations[role],op_rc[role],op_errno[role],tids[role]);
  }
  printf("],\"passed\":%s",k07_bool(valid));phase_end();
  struct kconc_regmap_status final;int rc=k07_get_status(device_fd,&final);
  valid &= rc==0 && k07_final_valid(&final,epoch,input,operations);
  bool allowed=final.max_depth<=1;
  printf("KCONC_PHASE {\"phase\":\"property\",\"passed\":%s,\"infrastructure_valid\":%s,"
    "\"oracle\":\"regmap-critical-region\",\"allowed\":%s,\"injected\":false,\"kernel_bug_claim\":false,"
    "\"caller_misuse_example\":true,\"status_rc\":%d,\"final\":",k07_bool(valid),k07_bool(valid),k07_bool(allowed),rc);
  k07_status_json(&final);phase_end();
  /* The controlled epoch is already reported. Progress uses a fresh epoch;
   * it does not overwrite busy evidence or count as another controlled run. */
  bool cleaned=teardown(valid);
  if (!cleaned || !valid) _exit(73);
}
