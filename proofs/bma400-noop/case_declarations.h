typedef unsigned long size_t;
typedef _Bool bool;
#define NULL ((void *)0)
#define EINVAL 22
#define IS_ALIGNED(x, a) (((x) & ((unsigned int)(a) - 1)) == 0)
enum regcache_type {
	REGCACHE_NONE, REGCACHE_RBTREE, REGCACHE_FLAT, REGCACHE_MAPLE, REGCACHE_FLAT_S
};
struct regmap_format {
	size_t val_bytes;
	void (*parse_inplace)(void *buf);
};
struct regmap {
	struct regmap_format format;
	int (*read)(void *context, const void *reg_buf, size_t reg_size,
		    void *val_buf, size_t val_size);
	int reg_stride;
	enum regcache_type cache_type;
};
extern bool regmap_volatile_range(struct regmap *map, unsigned int reg, size_t num);
extern int regmap_raw_read(struct regmap *map, unsigned int reg, void *val, size_t val_len);
extern int _regmap_bulk_read(struct regmap *map, unsigned int reg,
			     const unsigned int *regs, void *val, size_t val_count);
extern void trace_regmap_bulk_read(struct regmap *map, unsigned int reg,
				   const void *val, int val_len);
