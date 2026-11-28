obj-m += bma400_i2c_board.o
# The measured native driver is built into the kernel. This external board
# uses I2C core tracepoints; the patched KCOV hooks are kernel-internal.
KCOV_INSTRUMENT := n
