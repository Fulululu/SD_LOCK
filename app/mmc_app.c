#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <asm/types.h>
#include <linux/mmc/ioctl.h>

#include "mmc_ioctl.h"
#include "mmc.h"

static char pwd[] = {'m','s','1','2','3','4'};

/* You can get only lock/unlock status if card init failed*/
int get_status(int fd, unsigned int *response)
{
    int ret = 0;
    (void *)response;
    unsigned int status;
    
    ret = ioctl(fd, MMC_IOC_CMD_GET_STATUS, &status);
    if (ret)
        perror("ioctl");

    *response = status;
    return ret;
}

int card_set_pwd(int fd, unsigned int *response, struct mmc_pwd *pstpwd)
{
    int ret = 0;
    (void *)response;

    printf("app:len=%d, pwd=%s\n",pstpwd->len, pstpwd->ppwd);
    ret = ioctl(fd, MMC_IOC_CMD_SET_PWD, pstpwd);
    if (ret)
        perror("ioctl");

    return ret;
}

int card_clr_pwd(int fd, unsigned int *response, struct mmc_pwd *pstpwd)
{
    int ret = 0;
    (void *)response;
    
    printf("app:len=%d, pwd=%s\n",pstpwd->len, pstpwd->ppwd);
    ret = ioctl(fd, MMC_IOC_CMD_CLR_PWD, pstpwd);
    if (ret)
        perror("ioctl");

    return ret;
}

int lock_card(int fd, unsigned int *response, struct mmc_pwd *pstpwd)
{
    int ret = 0;
    (void *)response;
    
    printf("app:len=%d, pwd=%s\n",pstpwd->len, pstpwd->ppwd);
    ret = ioctl(fd, MMC_IOC_CMD_LOCK, pstpwd);
    if (ret)
        perror("ioctl");

    return ret;
}

int unlock_card(int fd, unsigned int *response, struct mmc_pwd *pstpwd)
{
    int ret = 0;
    (void *)response;

    ret = ioctl(fd, MMC_IOC_CMD_UNLOCK, pstpwd);
    if (ret)
        perror("ioctl");

    return ret;
}

int card_fe(int fd, unsigned int *response)
{
    int ret = 0;
    (void *)response;

    ret = ioctl(fd, MMC_IOC_CMD_FE);
    if (ret)
        perror("ioctl");

    return ret;
}

int main(int argc, char **argv)
{
    unsigned int response;
    int fd, ret;
    char *device;
    int ch;
    //opterr = 0;
    struct mmc_pwd stpwd;
    stpwd.len = sizeof(pwd);
    stpwd.ppwd = pwd;

    if (argc < 2) {
        printf("must input one arg at leaset!\n");
        exit(1);
    }

    fd = open("/dev/mmclock", O_RDWR);
    if (fd < 0) {
        perror("open");
        exit(1);
    }

    while((ch = getopt(argc, argv, "hgpclue")) != -1)
    {
        switch(ch)
        {
            case 'h':
            {
                printf("\n Args         Description\n");
                printf("------------------------------------\n");
                printf(" -h    print this help information\n");
                printf(" -g    get card status\n");
                printf(" -p    set password for card lock\n");
                printf(" -c    clear card lock password\n");
                printf(" -l    lock card\n");
                printf(" -u    unlock card\n");
                printf(" -e    force erase card\n\n");
                break;
            }
            case 'g':
            {
                ret = get_status(fd, &response);
                if (ret) {
                    printf("Could get status %s\n", device);
                    exit(1);
                }
                printf("\033[40;32mCard status: 0x%08x \033[0m\n", response);
                break;
            }
            case 'p':
            {
                ret = card_set_pwd(fd, &response, &stpwd);
                if (ret) {
                    printf("Could not lock %s\n", device);
                    exit(1);
                }
                //printf("\033[40;32m(userspace)card_set_pwd() success \033[0m\n");
                break;
            }
            case 'c':
            {
                ret = card_clr_pwd(fd, &response, &stpwd);
                if (ret) {
                    printf("Could not lock %s\n", device);
                    exit(1);
                }
                //printf("\033[40;32m(userspace)card_clr_pwd() success \033[0m\n");
                break;
            }
            case 'l':
            {
                ret = lock_card(fd, &response, &stpwd);
                if (ret) {
                    printf("Could not lock %s\n", device);
                    exit(1);
                }
                //printf("\033[40;32m(userspace)lock_card() success \033[0m\n");
                break;
            }
            case 'u':
            {
                ret = unlock_card(fd, &response, &stpwd);
                if (ret) {
                    printf("Could not unlock %s\n", device);
                    exit(1);
                }
                //printf("\033[40;32m(userspace)unlock_card() success \033[0m\n");
                break;
            }
            case 'e':
            {
                ret = card_fe(fd, &response);
                if (ret) {
                    printf("Could not lock %s\n", device);
                    exit(1);
                }
                //printf("\033[40;32m(userspace)card_fe() success \033[0m\n");
                break;
            }
            default:
                printf("other option :%c\n", ch);
        }
    }

    ret = close(fd);
    if(ret< 0){
        perror("close");
        exit(1);
    }

    return ret;
}
