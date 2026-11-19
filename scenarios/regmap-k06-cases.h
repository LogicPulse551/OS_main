/* SPDX-License-Identifier: GPL-2.0
 * Fixed caller-misuse examples. These definitions select real kernel requests;
 * the host independently recomputes the specification from exported inputs.
 */
#ifndef KCONC_REGMAP_K06_CASES_H
#define KCONC_REGMAP_K06_CASES_H
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include "kconc-regmap.h"

struct k06_input { unsigned int reg, mask, value; };
struct k06_case {
  const char *id;
  unsigned int initial[4];
  struct k06_input operations[2];
};
static const struct k06_case k06_cases[] = {
  {"disjoint-bits", {0,0,0,0}, {{0,1,1},{0,2,2}}},
  {"overlap-bits", {0,0,0,0}, {{0,3,1},{0,3,2}}},
  {"different-registers", {0,0,0,0}, {{0,1,1},{1,2,2}}},
  {"zero-mask", {0,0,0,0}, {{0,0,0},{0,2,2}}},
  {"high-bits", {0xa5a55a5aU,17,34,51},
    {{0,0x80000000U,0},{0,0x40000000U,0x40000000U}}}
};
#define K06_CASE_COUNT (sizeof(k06_cases)/sizeof(k06_cases[0]))
_Static_assert(sizeof(struct kconc_regmap_reset) == 32, "reset ABI");
_Static_assert(sizeof(struct kconc_regmap_op) == 64, "operation ABI");
_Static_assert(sizeof(struct kconc_regmap_status) == 136, "status ABI");
static inline const char *k06_bool(bool value) { return value ? "true" : "false"; }
static inline const char *k06_mode_name(unsigned int mode) {
  return mode == KCONC_REGMAP_MODE_SPLIT ? "split" : "update-bits";
}
static inline void k06_values_json(const unsigned int values[4]) {
  printf("[%u,%u,%u,%u]", values[0],values[1],values[2],values[3]);
}
static inline void k06_inputs_json(const struct k06_case *c) {
  printf("\"case_id\":\"%s\",\"initial\":",c->id); k06_values_json(c->initial);
  printf(",\"operations\":[");
  for (unsigned int i=0;i<2;++i) printf("%s{\"role\":%u,\"reg\":%u,\"mask\":%u,\"value\":%u}",
      i?",":"",i,c->operations[i].reg,c->operations[i].mask,c->operations[i].value);
  putchar(']');
}
static inline void k06_role_json(const struct kconc_regmap_role *s) {
  printf("{\"pid\":%u,\"checkpoint\":%u,\"preempt_count\":%u,\"irqs_disabled\":%u,"
    "\"before\":%u,\"after\":%u,\"reg\":%u,\"started\":%u,\"completed\":%u,\"status\":%d,"
    "\"mode\":%u,\"values_valid\":%u}", s->pid,s->checkpoint,s->preempt_count,s->irqs_disabled,
    s->before,s->after,s->reg,s->started,s->completed,s->status,s->mode,s->values_valid);
}
static inline void k06_status_json(const struct kconc_regmap_status *s) {
  printf("{\"abi\":%u,\"epoch\":%u,\"state\":%u,\"active\":%u,\"completed_mask\":%u,\"snapshot_valid\":%u,\"values\":",
      s->abi,s->epoch,s->state,s->active,s->completed_mask,s->snapshot_valid);
  k06_values_json(s->values); printf(",\"roles\":[");
  k06_role_json(&s->roles[0]); putchar(','); k06_role_json(&s->roles[1]); printf("]}");
}
static inline void k06_op_json(const struct kconc_regmap_op *s, int rc, int err, unsigned int tid) {
  printf("{\"abi\":%u,\"epoch\":%u,\"role\":%u,\"reg\":%u,\"mask\":%u,\"value\":%u,"
    "\"before\":%u,\"after\":%u,\"caller_tid\":%u,\"kernel_pid\":%u,\"checkpoint\":%u,"
    "\"preempt_count\":%u,\"irqs_disabled\":%u,\"status\":%d,\"mode\":%u,\"values_valid\":%u,"
    "\"reserved\":%u,\"rc\":%d,\"errno\":%d}", s->abi,s->epoch,s->role,s->reg,s->mask,s->value,
    s->before,s->after,tid,s->pid,s->checkpoint,s->preempt_count,s->irqs_disabled,s->status,
    s->mode,s->values_valid,s->reserved,rc,err);
}
static inline unsigned int k06_apply(unsigned int v, const struct k06_input *op) {
  return (v & ~op->mask) | (op->value & op->mask);
}
static inline bool k06_allowed(const struct k06_case *c, const unsigned int values[4]) {
  for (unsigned int first=0; first<2; ++first) {
    unsigned int expected[4]; memcpy(expected,c->initial,sizeof(expected));
    for (unsigned int n=0;n<2;++n) {
      const struct k06_input *op=&c->operations[first^n];
      expected[op->reg]=k06_apply(expected[op->reg],op);
    }
    if (!memcmp(expected,values,sizeof(expected))) return true;
  }
  return false;
}
static inline bool k06_roles_zero(const struct kconc_regmap_status *s) {
  const struct kconc_regmap_role zero={0};
  return !memcmp(&s->roles[0],&zero,sizeof(zero)) && !memcmp(&s->roles[1],&zero,sizeof(zero));
}
static inline bool k06_ready(const struct kconc_regmap_status *s,unsigned int epoch,const unsigned int values[4]) {
  return s->abi==KCONC_REGMAP_ABI && s->epoch==epoch && epoch && s->state==KCONC_REGMAP_READY &&
    !s->active && !s->completed_mask && s->snapshot_valid==1 && k06_roles_zero(s) &&
    !memcmp(s->values,values,4*sizeof(*values));
}
static inline bool k06_op_valid(const struct kconc_regmap_op *s,const struct k06_case *c,
    unsigned int role,unsigned int mode,unsigned int epoch,unsigned int tid,int rc,int err) {
  const struct k06_input *in=&c->operations[role];
  bool values=mode==KCONC_REGMAP_MODE_SPLIT ?
    s->values_valid==1 && s->after==k06_apply(s->before,in) :
    s->values_valid==0 && !s->before && !s->after;
  return rc==0 && err==0 && !s->status && s->abi==KCONC_REGMAP_ABI && s->epoch==epoch &&
    s->role==role && s->reg==in->reg && s->mask==in->mask && s->value==in->value &&
    s->mode==mode && !s->reserved && values && s->pid==tid && tid && s->checkpoint==epoch &&
    !s->preempt_count && !s->irqs_disabled;
}
static inline bool k06_slot_matches(const struct kconc_regmap_role *s,const struct kconc_regmap_op *op) {
  return s->started==1 && s->completed==1 && s->pid==op->pid && s->checkpoint==op->checkpoint &&
    s->preempt_count==op->preempt_count && s->irqs_disabled==op->irqs_disabled && s->before==op->before &&
    s->after==op->after && s->reg==op->reg && s->status==op->status && s->mode==op->mode && s->values_valid==op->values_valid;
}
static inline bool k06_empty(const struct kconc_regmap_status *s) {
  const unsigned int zeros[4]={0};
  return s->abi==KCONC_REGMAP_ABI && s->state==KCONC_REGMAP_EMPTY && !s->active && !s->completed_mask &&
    s->snapshot_valid==1 && k06_roles_zero(s) && !memcmp(s->values,zeros,sizeof(zeros));
}
#endif
