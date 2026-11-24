obj-m := regmap_three_check.o
KCOV_INSTRUMENT := n

FIXTURE_VARIANT ?= normal
ifeq ($(FIXTURE_VARIANT),normal)
ccflags-y += -DTRI_NORMAL_BUILD
else ifeq ($(FIXTURE_VARIANT),fault)
ccflags-y += -DTRI_FAULT_BUILD
else ifeq ($(FIXTURE_VARIANT),fixed)
ccflags-y += -DTRI_FIXED_BUILD
else
$(error FIXTURE_VARIANT must be normal, fault or fixed)
endif
