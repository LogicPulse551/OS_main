/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
#ifndef KCONC_REGMAP_NORMAL_UAPI_H
#define KCONC_REGMAP_NORMAL_UAPI_H

#include "kconc-regmap.h"

/* An independent normal-update session uses the same device and request types.
 * The larger status has its own ioctl encoding. ABI 2 keeps its original size.
 */
#define KCONC_REGMAP_NORMAL_ABI 3U
#define KCONC_REGMAP_NORMAL_ROLES 3U

struct kconc_regmap_normal_status {
	__u32 abi;
	__u32 epoch;
	__u32 state;
	__u32 active;
	__u32 completed_mask;
	__u32 snapshot_valid;
	__u32 values[KCONC_REGMAP_REGS];
	struct kconc_regmap_role roles[KCONC_REGMAP_NORMAL_ROLES];
};

#define KCONC_REGMAP_NORMAL_STATUS _IOWR('K', 0x52, struct kconc_regmap_normal_status)
#define KCONC_REGMAP_NORMAL_TEARDOWN _IOWR('K', 0x53, struct kconc_regmap_normal_status)

#endif
