KERNELDIR=/home/work/msallipc/XX.7.0.66/mskernel/hisi/src/kernel/linux-3.4.y

ARCH = arm
CROSS_COMPILE = /opt/hisi-linux/x86-arm/arm-hisiv300-linux/bin/arm-hisiv300-linux-uclibcgnueabi-

PWD:=$(shell pwd)
INSTALLDIR=/home/work/scp

obj-m += mmc_module.o
modules:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) modules ARCH=$(ARCH) CROSS_COMPILE=$(CROSS_COMPILE)
install:
	cp mmc_module.ko $(INSTALLDIR)
clean:
	rm -rf *.o *~ core .depend .*.cmd *.ko *.mod.c .tmp_versions *.order *.symvers
.PHONY: modules modules_install clean

