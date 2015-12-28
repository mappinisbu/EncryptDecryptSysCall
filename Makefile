obj-m += sys_xcrypt.o
ccflags-y := -std=gnu99 -Wno-declaration-after-statement

INC=/lib/modules/$(shell uname -r)/build/arch/x86/include

all: xcipher xcrypt

xcipher: xhw1.c
	gcc -Wall -Werror -lssl -I$(INC)/generated/uapi -I$(INC)/uapi xhw1.c -o xhw1

xcrypt:
	make -Wall -Werror -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
	rm -f xhw1
