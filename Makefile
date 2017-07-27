#Please don't touch this, I'm testing something out with the netfilter.c file
ifneq ($(KERNELRELEASE),)
obj-m := netfilter.o
else 
KDIR ?= /lib/modules/`uname -r`/build

default:
	$(MAKE) -C $(KDIR) M=$$PWD
endif
