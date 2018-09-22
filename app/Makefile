CROSS_COMPILE = /opt/hisi-linux/x86-arm/arm-hisiv300-linux/bin/arm-hisiv300-linux-uclibcgnueabi-
CC = $(CROSS_COMPILE)gcc
PWD:=$(shell pwd)
INSTALLDIR=/home/work/scp

all:mmc_app.o
	$(CC) mmc_app.o -o mmc_demo.app
mmc_app.o: mmc_app.c mmc_ioctl.h mmc.h
	$(CC) -c mmc_app.c

install:
	cp mmc_demo.app $(INSTALLDIR)
clean:
	rm -rf *.o *.app
.PHONY: install clean

