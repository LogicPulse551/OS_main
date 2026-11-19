/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
#ifndef KCONC_REGMAP_UAPI_H
#define KCONC_REGMAP_UAPI_H

#include <linux/ioctl.h>
#include <linux/types.h>

#define KCONC_REGMAP_ABI 1U
#define KCONC_REGMAP_REGS 4U
#define KCONC_REGMAP_ROLES 2U
#define KCONC_REGMAP_DEVICE "/dev/kconc-regmap"

#define KCONC_REGMAP_EMPTY 0U
#define KCONC_REGMAP_READY 1U
#define KCONC_REGMAP_POISONED 2U
#define KCONC_REGMAP_RESET_FAIL 1U

/* Fixed-width fields keep the ioctl layout identical for native/compat users. */
struct kconc_regmap_reset {
	__u32 abi;
	__u32 flags;
	__u32 initial[KCONC_REGMAP_REGS];
	__u32 epoch; /* output; zero is never a valid initialized epoch */
	__u32 reserved;
};

struct kconc_regmap_op {
	__u32 abi;
	__u32 epoch;
	__u32 role;
	__u32 reg;
	__u32 mask;
	__u32 value;
	__u32 before;
	__u32 after;
	__u32 pid;
	__u32 checkpoint;
	__u32 preempt_count;
	__u32 irqs_disabled;
	__s32 status;
	__u32 reserved;
};

struct kconc_regmap_role {
	__u32 pid;
	__u32 checkpoint;
	__u32 preempt_count;
	__u32 irqs_disabled;
	__u32 before;
	__u32 after;
	__u32 reg;
	__u32 started;
	__u32 completed;
	__s32 status;
};

struct kconc_regmap_status {
	__u32 abi;
	__u32 epoch;
	__u32 state;
	__u32 active;
	__u32 completed_mask;
	__u32 snapshot_valid; /* values/roles valid only when no operation is active */
	__u32 values[KCONC_REGMAP_REGS];
	struct kconc_regmap_role roles[KCONC_REGMAP_ROLES];
};

#define KCONC_REGMAP_RESET _IOWR('K', 0x50, struct kconc_regmap_reset)
#define KCONC_REGMAP_OP _IOWR('K', 0x51, struct kconc_regmap_op)
#define KCONC_REGMAP_STATUS _IOWR('K', 0x52, struct kconc_regmap_status)
#define KCONC_REGMAP_TEARDOWN _IOWR('K', 0x53, struct kconc_regmap_status)

#endif
