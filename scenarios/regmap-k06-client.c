/* SPDX-License-Identifier: GPL-2.0
 * Sequential AB/BA controls for each fixed input and both kernel operations.
 * These are oracle/reset checks, not concurrent replay attempts.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <unistd.h>
#include "regmap-k06-cases.h"
static int get_status(int fd,struct kconc_regmap_status *s) {
  *s=(struct kconc_regmap_status){.abi=KCONC_REGMAP_ABI};
  return ioctl(fd,KCONC_REGMAP_STATUS,s);
}
static int matrix(void) {
  int fd=open(KCONC_REGMAP_DEVICE,O_RDWR|O_CLOEXEC);
  if (fd<0) { printf("{\"kind\":\"kconc.regmap-rmw-matrix\",\"passed\":false,\"stage\":\"open\",\"errno\":%d}\n",errno); return 1; }
  bool passed=true;
  unsigned int previous_epoch=0,done=0,tid=(unsigned int)syscall(SYS_gettid);
  unsigned int requested=(unsigned int)K06_CASE_COUNT*4;
  printf("{\"schema_version\":1,\"kind\":\"kconc.regmap-rmw-matrix\",\"requested_rounds\":%u,\"caller_tid\":%u,\"rounds\":[",requested,tid);
  for (unsigned int c=0;c<K06_CASE_COUNT && passed;++c) {
    const struct k06_case *input=&k06_cases[c];
    for (unsigned int mode=0;mode<2 && passed;++mode) {
      for (unsigned int reverse=0;reverse<2 && passed;++reverse) {
        struct kconc_regmap_reset reset={.abi=KCONC_REGMAP_ABI};
        memcpy(reset.initial,input->initial,sizeof(reset.initial));
        int reset_rc=ioctl(fd,KCONC_REGMAP_RESET,&reset),reset_errno=reset_rc<0?errno:0;
        struct kconc_regmap_status initial;
        int initial_rc=get_status(fd,&initial);
        bool initial_ok=reset_rc==0 && initial_rc==0 && reset.epoch==previous_epoch+1 && k06_ready(&initial,reset.epoch,input->initial);
        bool row_ok=initial_ok;
        printf("%s{\"round\":%u,\"mode\":\"%s\",\"order\":\"%s\",\"inputs\":{",done?",":"",done,k06_mode_name(mode),reverse?"B-A":"A-B");
        k06_inputs_json(input);
        printf("},\"reset_rc\":%d,\"reset_errno\":%d,\"initial_rc\":%d,\"initial_passed\":%s,\"initial\":",reset_rc,reset_errno,initial_rc,k06_bool(initial_ok));
        k06_status_json(&initial); printf(",\"operations\":[");
        struct kconc_regmap_op operations[2]={{0}};
        unsigned int expected[4]; memcpy(expected,input->initial,sizeof(expected));
        for (unsigned int index=0;index<2 && initial_ok;++index) {
          unsigned int role=reverse^index;
          const struct k06_input *in=&input->operations[role];
          struct kconc_regmap_op *op=&operations[role];
          *op=(struct kconc_regmap_op){.abi=KCONC_REGMAP_ABI,.epoch=reset.epoch,.role=role,
            .reg=in->reg,.mask=in->mask,.value=in->value,.mode=mode};
          unsigned int before=expected[in->reg]; expected[in->reg]=k06_apply(before,in);
          int rc=ioctl(fd,KCONC_REGMAP_OP,op),err=rc<0?errno:0;
          row_ok &= k06_op_valid(op,input,role,mode,reset.epoch,tid,rc,err);
          if (mode==KCONC_REGMAP_MODE_SPLIT) row_ok &= op->before==before && op->after==expected[in->reg];
          if (index) putchar(',');
          k06_op_json(op,rc,err,tid);
        }
        struct kconc_regmap_status final;
        int final_rc=get_status(fd,&final);
        row_ok &= final_rc==0 && final.abi==KCONC_REGMAP_ABI && final.state==KCONC_REGMAP_READY &&
          final.snapshot_valid==1 && !final.active && final.epoch==reset.epoch && final.completed_mask==3 &&
          !memcmp(final.values,expected,sizeof(expected));
        for (unsigned int role=0;role<2;++role) row_ok &= k06_slot_matches(&final.roles[role],&operations[role]);
        bool allowed=k06_allowed(input,final.values); row_ok &= allowed;
        printf("],\"final_rc\":%d,\"final\":",final_rc); k06_status_json(&final);
        printf(",\"allowed\":%s,\"passed\":%s}",k06_bool(allowed),k06_bool(row_ok)); fflush(stdout);
        ++done; previous_epoch=reset.epoch; passed &= row_ok;
      }
    }
  }
  struct kconc_regmap_status torn={.abi=KCONC_REGMAP_ABI};
  int teardown_rc=ioctl(fd,KCONC_REGMAP_TEARDOWN,&torn),close_rc=close(fd);
  bool cleaned=teardown_rc==0 && k06_empty(&torn) && close_rc==0;
  passed &= cleaned && done==requested;
  printf("],\"completed_rounds\":%u,\"teardown_rc\":%d,\"close_rc\":%d,\"teardown\":",done,teardown_rc,close_rc);
  k06_status_json(&torn);
  printf(",\"resources_closed\":%s,\"passed\":%s,\"kernel_bug_claim\":false,\"caller_misuse_example\":true,"
    "\"scope\":\"Fixed real-regmap sequential AB/BA controls; not concurrent search or K10 replay acceptance\"}\n",
    k06_bool(cleaned),k06_bool(passed));
  return passed?0:1;
}
int main(int argc,char **argv) {
  if (argc==2 && !strcmp(argv[1],"matrix")) return matrix();
  fprintf(stderr,"Usage: %s matrix\n",argv[0]); return 2;
}
