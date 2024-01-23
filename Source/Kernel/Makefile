obj-m += magstat.o
PWD:= $(shell pwd)
UNAME:= $(shell uname -r)

all:
	make -C /lib/modules/$(UNAME)/build M=$(PWD) modules
clean:
	make -C /lib/modules/$(UNAME)/build M=$(PWD) clean
test:
	sudo dmesg -C
	sudo insmod magstat.ko
	sudo rmmod magstat.ko
	dmesg