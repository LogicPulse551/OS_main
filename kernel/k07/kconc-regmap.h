/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
#ifndef KCONC_REGMAP_UAPI_H
#define KCONC_REGMAP_UAPI_H

#include <linux/ioctl.h>
#include <linux/types.h>

#define KCONC_REGMAP_ABI 3U
#define KCONC_REGMAP_REGS 4U
#define KCONC_REGMAP_ROLES 2U
#define KCONC_REGMAP_EVENTS 4U
#define KCONC_REGMAP_DEVICE "/dev/kconc-regmap"
#define KCONC_REGMAP_EMPTY 0U
#define KCONC_REGMAP_READY 1U
#define KCONC_REGMAP_POISONED 2U
#define KCONC_REGMAP_RESET_FAIL 1U
#define KCONC_REGMAP_MODE_SHARED 0U
#define KCONC_REGMAP_MODE_PER_ROLE 1U
#define KCONC_REGMAP_OUTCOME_NONE 0U
#define KCONC_REGMAP_OUTCOME_SUCCESS 1U
#define KCONC_REGMAP_OUTCOME_BUSY 2U
#define KCONC_REGMAP_OUTCOME_ERROR 3U
#define KCONC_REGMAP_EVENT_ENTER 1U
#define KCONC_REGMAP_EVENT_EXIT 2U
#define KCONC_REGMAP_EVENT_BUSY 3U

/* Fixed-width fields keep the ioctl layout identical for native/compat users. */
struct kconc_regmap_reset {
	__u32 abi;
	__u32 flags;
	__u32 initial[KCONC_REGMAP_REGS];
	__u32 epoch;
	__u32 reserved;
};

struct kconc_regmap_role {
	__u32 pid;
	__u32 checkpoint;
	__u32 preempt_count;
	__u32 irqs_disabled;
	__u32 reg;
	__u32 started;
	__u32 completed;
	__s32 status;
	__u32 mode;
	__u32 gate_id; /* 0: shared gate; 1/2: role A/B private gates */
	__u32 acquired;
	__u32 outcome;
	__u32 enter_seq;
	__u32 enter_depth;
	__u32 exit_seq;
	__u32 exit_depth;
	__u32 busy_seq;
	__u32 busy_depth;
	__u32 api_calls;
	__u32 released;
};

struct kconc_regmap_op {
	__u32 abi;
	__u32 epoch;
	__u32 role;
	__u32 reg;
	__u32 mask;
	__u32 value;
	__u32 mode;
	__u32 reserved;
	struct kconc_regmap_role result;
};

struct kconc_regmap_event {
	__u32 seq;
	__u32 role;
	__u32 kind;
	__u32 depth; /* occupancy after this observed boundary */
};

struct kconc_regmap_status {
	__u32 abi;
	__u32 epoch;
	__u32 state;
	__u32 active;
	__u32 completed_mask;
	__u32 snapshot_valid; /* values/roles/events only valid while no ioctl is active */
	__u32 values[KCONC_REGMAP_REGS];
	struct kconc_regmap_role roles[KCONC_REGMAP_ROLES];
	__u32 event_count;
	__u32 in_cs;
	__u32 max_depth;
	__u32 gates_locked; /* bit 0 shared, bits 1/2 private A/B */
	struct kconc_regmap_event events[KCONC_REGMAP_EVENTS];
};

#define KCONC_REGMAP_RESET _IOWR('K', 0x50, struct kconc_regmap_reset)
#define KCONC_REGMAP_OP _IOWR('K', 0x51, struct kconc_regmap_op)
#define KCONC_REGMAP_STATUS _IOWR('K', 0x52, struct kconc_regmap_status)
#define KCONC_REGMAP_TEARDOWN _IOWR('K', 0x53, struct kconc_regmap_status)
#endif
