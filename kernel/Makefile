# Zygisk Virtualizer - Kernel Module (optional enhancement)
# This is NOT built by default. For advanced users who want
# kernel-level path virtualization instead of seccomp.

obj-m += virtualizer_kern.o

virtualizer_kern-objs := main.o

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
