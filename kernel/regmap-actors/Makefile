obj-m += regmap_actors.o
# The fixture uses public regmap APIs. The tracing helpers of the test kernel
# are private to built-in code and cannot be linked into an external module.
KCOV_INSTRUMENT_regmap_actors.o := n
