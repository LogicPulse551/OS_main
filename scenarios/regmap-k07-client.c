/* SPDX-License-Identifier: GPL-2.0
 * Sequential controls only, not concurrent exploration or stability sampling.
 */
#define _GNU_SOURCE
#include <fcntl.h>
#include "regmap-k07-cases.h"
static int matrix(void) {
  int fd=open(KCONC_REGMAP_DEVICE,O_RDWR|O_CLOEXEC);
  if (fd<0) { printf("{\"kind\":\"kconc.mutex-matrix\",\"passed\":false,\"stage\":\"open\",\"errno\":%d}\n",errno);return 1; }
  unsigned int epoch=0,done=0,requested=(unsigned int)K07_CASE_COUNT*4;bool passed=true;
  printf("{\"schema_version\":1,\"kind\":\"kconc.mutex-matrix\",\"requested_rounds\":%u,\"caller_tid\":%u,\"rounds\":[",requested,(unsigned int)syscall(SYS_gettid));
  for (unsigned int c=0;c<K07_CASE_COUNT && passed;++c)
    for (unsigned int mode=0;mode<2 && passed;++mode)
      for (unsigned int reverse=0;reverse<2 && passed;++reverse) {
        if (done) putchar(',');
        passed &= k07_sequential_json(fd,&k07_cases[c],mode,reverse,epoch+1,done,&epoch);
        ++done;fflush(stdout);
      }
  struct kconc_regmap_status empty={.abi=KCONC_REGMAP_ABI};
  int teardown_rc=ioctl(fd,KCONC_REGMAP_TEARDOWN,&empty),teardown_errno=teardown_rc<0?errno:0,close_rc=close(fd);
  bool cleaned=teardown_rc==0 && !teardown_errno && close_rc==0 && k07_empty(&empty,epoch);
  passed &= cleaned && done==requested;
  printf("],\"completed_rounds\":%u,\"teardown_rc\":%d,\"teardown_errno\":%d,\"close_rc\":%d,\"teardown\":",done,teardown_rc,teardown_errno,close_rc);
  k07_status_json(&empty);
  printf(",\"resources_closed\":%s,\"passed\":%s,\"kernel_bug_claim\":false,\"caller_misuse_example\":true,"
    "\"scope\":\"Eight sequential protocol controls, not concurrent search or stable replay\"}\n",k07_bool(cleaned),k07_bool(passed));
  return passed?0:1;
}
int main(int argc,char **argv) {
  if (argc==2 && !strcmp(argv[1],"matrix")) return matrix();
  fprintf(stderr,"Usage: %s matrix\n",argv[0]);return 2;
}
