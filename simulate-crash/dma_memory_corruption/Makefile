# Makefile for DMA Memory Corruption Simulator kernel module
# Build: make            (cross build: make KERNEL_DIR=/usr/src/kernels/<version>)
# Clean: make clean

KERNEL_DIR ?= /lib/modules/$(shell uname -r)/build

obj-m += dma_memory_corruption_mod.o

# Keep debug info (-g) so crash can map addresses to file:line.
# Do NOT use -O0/-Og: the kernel only supports -O2/-Os. Functions that must keep
# their own stack frame (e.g. simulate_dma_write) are marked noinline in the source.
ccflags-y := -g -DDEBUG

# GCC compatibility options
ccflags-y += -Wno-error=address-of-packed-member -Wno-error=restrict

# Verbose kbuild output (V=0 to silence)
V ?= 1

.PHONY: all clean vermagic

all:
	$(MAKE) -C $(KERNEL_DIR) M=$(CURDIR) modules V=$(V)

clean:
	$(MAKE) -C $(KERNEL_DIR) M=$(CURDIR) clean V=$(V)

# vermagic must match the target kernel, e.g. 5.14.0-362.24.1.el9_3.x86_64
vermagic:
	@modinfo -F vermagic dma_memory_corruption_mod.ko
