#ifndef __MMC_IOCTL_H__
#define __MMC_IOCTL_H__

//#include <linux/ioctl.h>    // kernel space
#include <sys/ioctl.h>     // user space

#define MMC_IOC_LOCK_MAGIC      'k'

#define MMC_IOC_CMD_SET_PWD     _IOW(MMC_IOC_LOCK_MAGIC, 0x1a, struct mmc_pwd)
#define MMC_IOC_CMD_CLR_PWD     _IOW(MMC_IOC_LOCK_MAGIC, 0x1b, struct mmc_pwd)
#define MMC_IOC_CMD_LOCK        _IOW(MMC_IOC_LOCK_MAGIC, 0x1c, struct mmc_pwd)
#define MMC_IOC_CMD_UNLOCK      _IOW(MMC_IOC_LOCK_MAGIC, 0x1d, struct mmc_pwd)
#define MMC_IOC_CMD_FE          _IO(MMC_IOC_LOCK_MAGIC, 0x1e)
#define MMC_IOC_CMD_GET_STATUS  _IOR(MMC_IOC_LOCK_MAGIC, 0x1f, unsigned int)

#define IOC_MAXNR               6

struct mmc_pwd{
        unsigned char len;
        char *ppwd;
};
#endif