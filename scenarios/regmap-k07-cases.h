/* SPDX-License-Identifier: GPL-2.0
 * Fixed nonblocking caller-protocol examples over the real kernel regmap.
 */
#ifndef KCONC_REGMAP_K07_CASES_H
#define KCONC_REGMAP_K07_CASES_H
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <unistd.h>
#include "kconc-regmap.h"

struct k07_input { unsigned int reg, mask, value; };
struct k07_case { const char *id; unsigned int initial[4]; struct k07_input operations[2]; };
static const struct k07_case k07_cases[] = {
  {"different-registers", {0,0,0,0}, {{0,1,1},{1,2,2}}},
  {"shared-register", {0,0,0,0}, {{0,1,1},{0,2,2}}}
};
#define K07_CASE_COUNT (sizeof(k07_cases)/sizeof(k07_cases[0]))
_Static_assert(sizeof(struct kconc_regmap_reset)==32,"reset ABI");
_Static_assert(sizeof(struct kconc_regmap_role)==80,"role ABI");
_Static_assert(sizeof(struct kconc_regmap_op)==112,"operation ABI");
_Static_assert(sizeof(struct kconc_regmap_status)==280,"status ABI");
static inline const char *k07_bool(bool x) { return x?"true":"false"; }
static inline const char *k07_mode(unsigned int x) { return x?"per-role":"shared"; }
static inline void k07_values_json(const unsigned int *v) { printf("[%u,%u,%u,%u]",v[0],v[1],v[2],v[3]); }
static inline void k07_inputs_json(const struct k07_case *c) {
  printf("\"case_id\":\"%s\",\"initial\":",c->id);k07_values_json(c->initial);printf(",\"operations\":[");
  for (unsigned int i=0;i<2;++i) printf("%s{\"role\":%u,\"reg\":%u,\"mask\":%u,\"value\":%u}",
    i?",":"",i,c->operations[i].reg,c->operations[i].mask,c->operations[i].value);
  putchar(']');
}
static inline void k07_reset_json(const struct kconc_regmap_reset *r) {
  printf("{\"abi\":%u,\"flags\":%u,\"initial\":",r->abi,r->flags);k07_values_json(r->initial);
  printf(",\"epoch\":%u,\"reserved\":%u}",r->epoch,r->reserved);
}
static inline void k07_role_json(const struct kconc_regmap_role *s) {
  printf("{\"pid\":%u,\"checkpoint\":%u,\"preempt_count\":%u,\"irqs_disabled\":%u,"
    "\"reg\":%u,\"started\":%u,\"completed\":%u,\"status\":%d,\"mode\":%u,\"gate_id\":%u,"
    "\"acquired\":%u,\"outcome\":%u,\"enter_seq\":%u,\"enter_depth\":%u,\"exit_seq\":%u,\"exit_depth\":%u,"
    "\"busy_seq\":%u,\"busy_depth\":%u,\"api_calls\":%u,\"released\":%u}",
    s->pid,s->checkpoint,s->preempt_count,s->irqs_disabled,s->reg,s->started,s->completed,s->status,
    s->mode,s->gate_id,s->acquired,s->outcome,s->enter_seq,s->enter_depth,s->exit_seq,s->exit_depth,
    s->busy_seq,s->busy_depth,s->api_calls,s->released);
}
static inline void k07_status_json(const struct kconc_regmap_status *s) {
  printf("{\"abi\":%u,\"epoch\":%u,\"state\":%u,\"active\":%u,\"completed_mask\":%u,\"snapshot_valid\":%u,\"values\":",
    s->abi,s->epoch,s->state,s->active,s->completed_mask,s->snapshot_valid);k07_values_json(s->values);
  printf(",\"roles\":[");k07_role_json(&s->roles[0]);putchar(',');k07_role_json(&s->roles[1]);
  printf("],\"event_count\":%u,\"in_cs\":%u,\"max_depth\":%u,\"gates_locked\":%u,\"events\":[",
    s->event_count,s->in_cs,s->max_depth,s->gates_locked);
  for (unsigned int i=0;i<KCONC_REGMAP_EVENTS;++i) {
    const struct kconc_regmap_event *e=&s->events[i];
    printf("%s{\"seq\":%u,\"role\":%u,\"kind\":%u,\"depth\":%u}",i?",":"",e->seq,e->role,e->kind,e->depth);
  }
  printf("]}");
}
static inline void k07_op_json(const struct kconc_regmap_op *s,int rc,int err,unsigned int tid) {
  printf("{\"abi\":%u,\"epoch\":%u,\"role\":%u,\"reg\":%u,\"mask\":%u,\"value\":%u,\"mode\":%u,"
    "\"reserved\":%u,\"caller_tid\":%u,\"rc\":%d,\"errno\":%d,\"result\":",
    s->abi,s->epoch,s->role,s->reg,s->mask,s->value,s->mode,s->reserved,tid,rc,err);
  k07_role_json(&s->result);putchar('}');
}
static inline bool k07_zero_metadata(const struct kconc_regmap_status *s) {
  const struct kconc_regmap_role r={0};const struct kconc_regmap_event e={0};
  if (s->active || s->completed_mask || s->event_count || s->in_cs || s->max_depth || s->gates_locked) return false;
  for (unsigned int i=0;i<2;++i) if (memcmp(&s->roles[i],&r,sizeof(r))) return false;
  for (unsigned int i=0;i<KCONC_REGMAP_EVENTS;++i) if (memcmp(&s->events[i],&e,sizeof(e))) return false;
  return true;
}
static inline bool k07_ready(const struct kconc_regmap_status *s,unsigned int epoch,const unsigned int initial[4]) {
  return s->abi==KCONC_REGMAP_ABI && s->epoch==epoch && epoch && s->state==KCONC_REGMAP_READY &&
    s->snapshot_valid==1 && k07_zero_metadata(s) && !memcmp(s->values,initial,4*sizeof(*initial));
}
static inline bool k07_empty(const struct kconc_regmap_status *s,unsigned int epoch) {
  const unsigned int zero[4]={0};
  return s->abi==KCONC_REGMAP_ABI && s->epoch==epoch && s->state==KCONC_REGMAP_EMPTY &&
    s->snapshot_valid==1 && k07_zero_metadata(s) && !memcmp(s->values,zero,sizeof(zero));
}
static inline bool k07_op_valid(const struct kconc_regmap_op *op,const struct k07_case *c,
    unsigned int role,unsigned int mode,unsigned int epoch,unsigned int tid,int rc,int err) {
  const struct k07_input *in=&c->operations[role];const struct kconc_regmap_role *r=&op->result;
  bool base=op->abi==KCONC_REGMAP_ABI && op->epoch==epoch && op->role==role && op->reg==in->reg &&
    op->mask==in->mask && op->value==in->value && op->mode==mode && !op->reserved && r->pid==tid && tid &&
    r->reg==in->reg && r->mode==mode && r->gate_id==(mode?role+1:0) && r->started==1 && r->completed==1 &&
    !r->preempt_count && !r->irqs_disabled;
  if (r->outcome==KCONC_REGMAP_OUTCOME_SUCCESS)
    return base && rc==0 && !err && !r->status && r->acquired==1 && r->released==1 && r->api_calls==1 &&
      r->checkpoint==epoch && r->enter_seq && r->exit_seq>r->enter_seq && r->enter_depth>=1 && r->enter_depth<=2 &&
      r->exit_depth<=1 && !r->busy_seq && !r->busy_depth;
  if (r->outcome==KCONC_REGMAP_OUTCOME_BUSY)
    return base && rc==-1 && err==EBUSY && r->status==-EBUSY && !r->acquired && !r->released && !r->api_calls &&
      !r->checkpoint && !r->enter_seq && !r->exit_seq && !r->enter_depth && !r->exit_depth && r->busy_seq && r->busy_depth<=2;
  return false;
}
static inline int k07_get_status(int fd,struct kconc_regmap_status *s) {
  *s=(struct kconc_regmap_status){.abi=KCONC_REGMAP_ABI};return ioctl(fd,KCONC_REGMAP_STATUS,s);
}
static inline void k07_apply(unsigned int values[4],const struct k07_input *op) {
  values[op->reg]=(values[op->reg]&~op->mask)|(op->value&op->mask);
}
static inline bool k07_final_valid(const struct kconc_regmap_status *s,unsigned int epoch,
    const struct k07_case *c,const struct kconc_regmap_op operations[2]) {
  unsigned int expected[4];memcpy(expected,c->initial,sizeof(expected));
  if (s->abi!=KCONC_REGMAP_ABI || s->epoch!=epoch || s->state!=KCONC_REGMAP_READY || s->active ||
      s->snapshot_valid!=1 || s->completed_mask!=3 || s->in_cs || s->gates_locked || s->event_count>4) return false;
  for (unsigned int i=0;i<2;++i) {
    if (memcmp(&s->roles[i],&operations[i].result,sizeof(s->roles[i]))) return false;
    if (operations[i].result.outcome==KCONC_REGMAP_OUTCOME_SUCCESS) k07_apply(expected,&c->operations[i]);
  }
  return !memcmp(s->values,expected,sizeof(expected));
}
/* Print one complete sequential round. It is separate from a recorded trace. */
static inline bool k07_sequential_json(int fd,const struct k07_case *input,unsigned int mode,
    unsigned int reverse,unsigned int expected_epoch,unsigned int round,unsigned int *actual_epoch) {
  unsigned int tid=(unsigned int)syscall(SYS_gettid);
  struct kconc_regmap_reset reset={.abi=KCONC_REGMAP_ABI};memcpy(reset.initial,input->initial,sizeof(reset.initial));
  int reset_rc=ioctl(fd,KCONC_REGMAP_RESET,&reset),reset_errno=reset_rc<0?errno:0;
  *actual_epoch=reset.epoch;
  struct kconc_regmap_status initial;int initial_rc=k07_get_status(fd,&initial);
  bool initial_ok=reset_rc==0 && !reset_errno && initial_rc==0 && reset.epoch==expected_epoch &&
    k07_ready(&initial,expected_epoch,input->initial),passed=initial_ok;
  printf("{\"round\":%u,\"mode\":\"%s\",\"order\":\"%s\",\"caller_tid\":%u,\"inputs\":{",
    round,k07_mode(mode),reverse?"B-A":"A-B",tid);k07_inputs_json(input);
  printf("},\"reset\":");k07_reset_json(&reset);
  printf(",\"reset_rc\":%d,\"reset_errno\":%d,\"initial_rc\":%d,\"initial_passed\":%s,\"initial\":",
    reset_rc,reset_errno,initial_rc,k07_bool(initial_ok));k07_status_json(&initial);printf(",\"operations\":[");
  struct kconc_regmap_op operations[2]={{0}};
  for (unsigned int n=0;n<2 && initial_ok;++n) {
    unsigned int role=reverse^n;const struct k07_input *in=&input->operations[role];struct kconc_regmap_op *op=&operations[role];
    *op=(struct kconc_regmap_op){.abi=KCONC_REGMAP_ABI,.epoch=reset.epoch,.role=role,.reg=in->reg,.mask=in->mask,.value=in->value,.mode=mode};
    int rc=ioctl(fd,KCONC_REGMAP_OP,op),err=rc<0?errno:0;
    passed &= k07_op_valid(op,input,role,mode,reset.epoch,tid,rc,err) && op->result.outcome==KCONC_REGMAP_OUTCOME_SUCCESS;
    if (n) putchar(',');
    k07_op_json(op,rc,err,tid);
  }
  struct kconc_regmap_status final;int final_rc=k07_get_status(fd,&final);
  passed &= final_rc==0 && k07_final_valid(&final,reset.epoch,input,operations) && final.event_count==4 && final.max_depth==1;
  bool allowed=final.max_depth<=1;
  printf("],\"final_rc\":%d,\"final\":",final_rc);k07_status_json(&final);
  printf(",\"allowed\":%s,\"passed\":%s}",k07_bool(allowed),k07_bool(passed));
  return passed;
}
#endif
