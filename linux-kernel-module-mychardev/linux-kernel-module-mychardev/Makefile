obj-m := mychardev.o

KDIR ?= /lib/modules/$(shell uname -r)/build
PWD  := $(shell pwd)

all:
	$(MAKE) -C $(KDIR) M=$(PWD) modules
	gcc -Wall -Wextra -Werror -O2 -o test_user test_user.c

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean

load:
	sudo insmod mychardev.ko

unload:
	sudo rmmod mychardev

watch: all
	./test_user --watch 30

