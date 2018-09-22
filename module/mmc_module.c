#include <linux/init.h>
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/cdev.h>
#include <asm/uaccess.h>
#include <linux/miscdevice.h>
#include <linux/slab.h>
#include "mmc_ioctl.h"

MODULE_LICENSE("Dual BSD/GPL");
MODULE_AUTHOR("ygf@milesight.com");

struct mmc_pwd st_ioctl_pwd = {0, NULL};

extern int mmc_card_set_pwd(struct mmc_pwd *pst_mmc_pwd);
extern int mmc_card_clr_pwd(struct mmc_pwd *pst_mmc_pwd);
extern int mmc_lock_card(struct mmc_pwd *pst_mmc_pwd);
extern int mmc_unlock_card(struct mmc_pwd *pst_mmc_pwd);
extern int mmc_card_fe(void);
extern int mmc_card_send_status(unsigned int *status);

static int mmc_lock_open(struct inode *inode, struct file *file)
{
    printk("MMC lock control device open!\n");
    return 0;
}

static int mmc_lock_release(struct inode *inode, struct file *file)
{
    printk("MMC lock control device release!\n");
    return 0;
}

static int mmc_lock_copy_from_user(struct mmc_pwd __user *user_mmc_pwd)
{
    int ret = 0;
    char *tmp_ptr = NULL;
    static int ppwd_init = 0;
    
    ret = copy_from_user(&st_ioctl_pwd.len, &user_mmc_pwd->len, sizeof(int));
    if (ret)
        return -EFAULT;
    
    if (ppwd_init == 0)
    {
        tmp_ptr = (char *)kmalloc(st_ioctl_pwd.len * sizeof(char), GFP_KERNEL);
        if (NULL == tmp_ptr)
        {
            return -EFAULT;
        }
        ppwd_init = 1;
    }
    else
    {
        kfree(st_ioctl_pwd.ppwd);
        tmp_ptr = (char *)kmalloc(st_ioctl_pwd.len * sizeof(char), GFP_KERNEL);
        if (NULL == tmp_ptr)
        {
            return -EFAULT;
        }
    }
    memset(tmp_ptr, 0, st_ioctl_pwd.len * sizeof(char));
    ret = copy_from_user(tmp_ptr, user_mmc_pwd->ppwd, st_ioctl_pwd.len * sizeof(char));
    if (ret)
        return -EFAULT;
    st_ioctl_pwd.ppwd = tmp_ptr;
    
    return ret;
}

static long mmc_lock_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
    int idx = 0, ret;
    unsigned int status;

    switch(cmd)
    {
        case MMC_IOC_CMD_SET_PWD:
        {
            idx = 1;
            ret = mmc_lock_copy_from_user((struct mmc_pwd __user *)arg);
            if (ret) 
                return -EFAULT;
            ret = mmc_card_set_pwd(&st_ioctl_pwd);
            if (ret) 
                return -EFAULT;
            break;
        }
        case MMC_IOC_CMD_CLR_PWD:
        {
            idx = 2;
            ret = mmc_lock_copy_from_user((struct mmc_pwd __user *)arg);
            if (ret)
                return -EFAULT;
            //printk("(kernelspace)[%p]=%d, *[%p]=%s",&st_ioctl_pwd.len,st_ioctl_pwd.len,&st_ioctl_pwd.ppwd,st_ioctl_pwd.ppwd);
            ret = mmc_card_clr_pwd(&st_ioctl_pwd);
            if (ret)
                return -EFAULT;
            break;
        }
        case MMC_IOC_CMD_LOCK:
        {
            idx = 3;
            ret = mmc_lock_copy_from_user((struct mmc_pwd __user *)arg);
            if (ret) 
                return -EFAULT;
            ret = mmc_lock_card(&st_ioctl_pwd);
            if (ret) 
                return -EFAULT;
            break;
        }
        case MMC_IOC_CMD_UNLOCK:
        {
            idx = 4;
            ret = mmc_lock_copy_from_user((struct mmc_pwd __user *)arg);
            if (ret) 
                return -EFAULT;
            ret = mmc_unlock_card(&st_ioctl_pwd);
            if (ret) 
                return -EFAULT;
            break;
        }
        case MMC_IOC_CMD_FE:
        {
            idx = 5;
            ret = mmc_card_fe();
            if (ret) 
                return -EFAULT;
            break;
        }
        case MMC_IOC_CMD_GET_STATUS:
        {
            idx = 6;
            ret = mmc_card_send_status(&status);
            if (ret) 
                return -EFAULT;
            ret = copy_to_user((unsigned int *)arg, &status, sizeof(unsigned int));
            if (ret)
                return -EFAULT;
            break;
        }
        default:
            return -ENOTTY;
    }
    //printk(KERN_NOTICE "(kernelspace)IOCTL:CMD%d done!\n",idx);
    //printk(KERN_NOTICE "IOCTL: len(pwd)=%d, pwd=%s",st_ioctl_pwd.len,st_ioctl_pwd.ppwd); 

    return 0;
}

/* file operations for test device */
static struct file_operations mmc_lock_fops = {
    .owner = THIS_MODULE,
    .open = mmc_lock_open,
    .release = mmc_lock_release,
    //.read = mmc_lock_read,
    //.write = mmc_lock_write,
    .unlocked_ioctl = mmc_lock_ioctl,
};

static struct miscdevice hi_mmc_lock_miscdev =
{
    .minor = MISC_DYNAMIC_MINOR,
    .name  = "mmclock",
    .fops  = &mmc_lock_fops,
};

static int __init mmc_lock_init(void)
{
	int res = 0;
	
	res = misc_register(&hi_mmc_lock_miscdev);
	if( res < 0 )
	{
		printk(KERN_INFO "misc_register mmc lock module failed\n");
		return -EFAULT;
	}

	printk(KERN_INFO "mmc lock module initialized!\n");
	
	return res;
}

static void __exit mmc_lock_exit(void)
{
	misc_deregister(&hi_mmc_lock_miscdev);
	printk("mmc lock module uninstalled!\n");
}

module_init(mmc_lock_init);
module_exit(mmc_lock_exit);
