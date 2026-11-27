# Makefile for Soft Lockup Simulation Module

# Kernel build directory; override for cross builds, e.g.
#   make KERNEL_DIR=/usr/src/kernels/5.14.0-362.24.1.el9_3.x86_64
KERNEL_DIR ?= /lib/modules/$(shell uname -r)/build
PWD := $(shell pwd)

MODULE := soft_lockup_module
obj-m := $(MODULE).o

# Always keep debug info (-g) so crash can map addresses to file:line.
# Do NOT use -O0: the kernel only supports -O2/-Os. Stack readability comes from
# -g plus noinline on the functions that must appear in backtraces.
DEBUG ?= 1
ccflags-y := -g
ifeq ($(DEBUG),1)
ccflags-y += -DDEBUG
endif

CPU ?= 2
# spinlock mode: CPU for the contending thread
CPU2 ?= 1

all:
	$(MAKE) -C $(KERNEL_DIR) M=$(PWD) modules

clean:
	$(MAKE) -C $(KERNEL_DIR) M=$(PWD) clean

install:
	sudo $(MAKE) -C $(KERNEL_DIR) M=$(PWD) modules_install
	sudo depmod -a

# Load and start the lockup immediately on any CPU
load:
	sudo insmod $(MODULE).ko enable_soft_lockup=1

# Load and start the lockup on a specific CPU: make load_cpu CPU=2
load_cpu:
	sudo insmod $(MODULE).ko enable_soft_lockup=1 cpu_number=$(CPU)

# spinlock mode: holder on $(CPU), contender on $(CPU2)
load_spinlock:
	sudo insmod $(MODULE).ko mode=spinlock enable_soft_lockup=1 cpu_number=$(CPU) contender_cpu=$(CPU2)

# softirq mode: busy-wait inside a timer softirq callback on $(CPU)
load_softirq:
	sudo insmod $(MODULE).ko mode=softirq enable_soft_lockup=1 cpu_number=$(CPU)

# irqoff mode (DANGEROUS): hard lockup via NMI watchdog; may hang the whole system
load_irqoff:
	sudo insmod $(MODULE).ko mode=irqoff allow_irqoff=1 enable_soft_lockup=1 cpu_number=$(CPU)

# Load without triggering; use "make start" later
load_idle:
	sudo insmod $(MODULE).ko cpu_number=$(CPU)

# Runtime switch via sysfs
start:
	echo 1 | sudo tee /sys/module/$(MODULE)/parameters/enable_soft_lockup

stop:
	echo 0 | sudo tee /sys/module/$(MODULE)/parameters/enable_soft_lockup

unload:
	sudo rmmod $(MODULE)

reload: unload load

info:
	modinfo $(MODULE).ko

# vermagic must match the target kernel, e.g. 5.14.0-362.24.1.el9_3.x86_64
vermagic:
	@modinfo -F vermagic $(MODULE).ko

kernel_version:
	@echo "Current kernel version: $(shell uname -r)"

status:
	@lsmod | grep $(MODULE) || echo "Module not loaded"

compile_and_install: all install

.PHONY: all clean install load load_cpu load_spinlock load_softirq load_irqoff load_idle start stop unload reload info vermagic kernel_version status compile_and_install
