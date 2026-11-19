obj-m += kconc_fifo.o
kconc_fifo-y := bench.o service.o
FIFO_VARIANT ?= 0
ccflags-y += -DFIFO_VARIANT=$(FIFO_VARIANT)
ifneq ($(filter 1 2,$(FIFO_VARIANT)),)
kconc_fifo-y += boundary.o
endif
