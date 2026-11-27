# Makefile for RCU Stall Simulator kernel module
# Build: make            (cross build: make KERNEL_DIR=/usr/src/kernels/<version>)
# Clean: make clean

KERNEL_DIR ?= /lib/modules/$(shell uname -r)/build

obj-m += rcu_stall_mod.o

# Keep debug info (-g) so crash can map addresses to file:line.
# Do NOT use -O0: the kernel only supports -O2/-Os. The thread functions are
# passed to kthread_create() as function pointers, so they keep their own stack
# frames without -fno-inline; mark any other function that must appear in a
# backtrace with noinline instead.
ccflags-y := -g -DDEBUG

# Verbose kbuild output (V=0 to silence)
V ?= 1

.PHONY: all clean vermagic

all:
	$(MAKE) -C $(KERNEL_DIR) M=$(CURDIR) modules V=$(V)

clean:
	$(MAKE) -C $(KERNEL_DIR) M=$(CURDIR) clean V=$(V)

# vermagic must match the target kernel, e.g. 5.14.0-362.24.1.el9_3.x86_64
vermagic:
	@modinfo -F vermagic rcu_stall_mod.ko
