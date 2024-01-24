obj-m += stats.o
stats-y := main.o stats/cpustats.o

PWD:= $(shell pwd)
UNAME:= $(shell uname -r)

all:
	make -C /lib/modules/$(UNAME)/build M=$(PWD) modules
clean:
	make -C /lib/modules/$(UNAME)/build M=$(PWD) clean
