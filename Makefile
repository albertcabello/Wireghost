TARGET = wireghost
obj-m += $(TARGET).o
wireghost-objs := netfilter.o dictionary.o
#ccflags-$(CONFIG_ACPI_DEBUG) += -Wdeclaration-after-statement
all :
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules
clean :
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
