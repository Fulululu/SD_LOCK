/*
 *  linux/drivers/mmc/core/mmc_ops.h
 *
 *  Copyright 2006-2007 Pierre Ossman
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or (at
 * your option) any later version.
 */

#include <linux/slab.h>
#include <linux/export.h>
#include <linux/types.h>
#include <linux/scatterlist.h>

#include <linux/completion.h>

#include <linux/mmc/host.h>
#include <linux/mmc/card.h>
#include <linux/mmc/mmc.h>
#include <linux/mmc/sd.h>

#include "core.h"
#include "mmc_ops.h"
#include "../host/himci/hi_mci.h"

struct completion mmc_lock_comp;
struct mmc_pwd_admin g_pwd_store = {{0, NULL}, {0, NULL}};

static int mmc_save_pwd(struct    mmc_pwd *pdest_mmc_pwd, struct mmc_pwd *psrc_mmc_pwd)
{
    static int pwd_init = 0;

    if (psrc_mmc_pwd->len != 0 && psrc_mmc_pwd->ppwd != NULL)
    {
        if (!pwd_init)
        {
            pdest_mmc_pwd->ppwd = (char *)kmalloc(psrc_mmc_pwd->len * sizeof(char), GFP_KERNEL);
            if (NULL == pdest_mmc_pwd->ppwd)
            {
                return -1;
            }
            pwd_init = 1;
        }
        else
        {
            kfree(pdest_mmc_pwd->ppwd);
            pdest_mmc_pwd->ppwd = (char *)kmalloc(psrc_mmc_pwd->len * sizeof(char), GFP_KERNEL);
            if (NULL == pdest_mmc_pwd->ppwd)
            {
                return -1;
            }
        }
        
        pdest_mmc_pwd->len = psrc_mmc_pwd->len;
        memcpy(pdest_mmc_pwd->ppwd, psrc_mmc_pwd->ppwd, psrc_mmc_pwd->len*sizeof(char));
        pdest_mmc_pwd->ppwd[pdest_mmc_pwd->len] = '\0';
        return 0;
    }
    else
    {
        printk("mmc_save_pwd():src_mmc_pwd member is 0 or null.\n");
        return -1;
    }
}

static int mmc_save_pwd_tmp(struct    mmc_pwd *pdest_mmc_pwd, struct mmc_pwd *psrc_mmc_pwd)
{
    static int pwd_tmp_init = 0;

    if (psrc_mmc_pwd->len != 0 && psrc_mmc_pwd->ppwd != NULL)
    {
        if (!pwd_tmp_init)
        {
            pdest_mmc_pwd->ppwd = (char *)kmalloc(psrc_mmc_pwd->len * sizeof(char), GFP_KERNEL);
            if (NULL == pdest_mmc_pwd->ppwd)
            {
                return -1;
            }
            pwd_tmp_init = 1;
        }
        else
        {
            kfree(pdest_mmc_pwd->ppwd);
            pdest_mmc_pwd->ppwd = (char *)kmalloc(psrc_mmc_pwd->len * sizeof(char), GFP_KERNEL);
            if (NULL == pdest_mmc_pwd->ppwd)
            {
                return -1;
            }
        }
        
        pdest_mmc_pwd->len = psrc_mmc_pwd->len;
        memcpy(pdest_mmc_pwd->ppwd, psrc_mmc_pwd->ppwd, psrc_mmc_pwd->len*sizeof(char));       
        pdest_mmc_pwd->ppwd[pdest_mmc_pwd->len] = '\0';
        return 0;
    }
    else
    {
        return -1;
    }
}

static int mmc_set_pwd(u8 mode, struct mmc_pwd *pst_mmc_pwd)
{
    u32 err;

    if(SD_SET_PWD == mode || SD_UNLOCK_PWD == mode)
    {
        err = mmc_save_pwd(&g_pwd_store.stpwd, pst_mmc_pwd);
        if (err)
        {
            printk("mmc_set_pwd() failed.\n");
            return err;
        }
    }
    
    if(SD_CLEAR_PWD == mode || SD_UNLOCK_PWD == mode || SD_LOCK_PWD == mode)
    {
        g_pwd_store.temp_pwd.len = 0;
    }
    
    if(SD_CLEAR_PWD == mode || SD_FORCE_ERASE == mode)
    {
        g_pwd_store.stpwd.len = 0;
    }

    return 0;
}

int mmc_send_cmd42(struct mmc_card *card, u8 mode, struct mmc_pwd *pst_mmc_pwd)
{
    struct mmc_request mrq = {NULL};
    struct mmc_command cmd = {0};
    struct mmc_data data = {0};
    struct scatterlist sg;
    u32 err = -1;
    //u32 status;
    u8 *tmp_buf = NULL;
    //u64 fe_timeout;

    if(g_stlockattr.init_status)
    {
        mmc_claim_host(card->host);
    }

    // Set length of CMD42 Block 
	cmd.opcode = MMC_SET_BLOCKLEN;
	cmd.arg = 512;
	cmd.flags = MMC_RSP_R1 | MMC_CMD_AC;
	mmc_wait_for_cmd(card->host, &cmd, 0);
	if (cmd.error)
	{
        printk(KERN_INFO "\033[40;32m SET_BLOCKLEN for CMD42 error(0x%x)! return 0x%x \033[0m\n",cmd.error, cmd.resp[0]);
		err = cmd.error;
        goto err_exit;
	}
    
    // Pack structure
    mrq.cmd = &cmd;
    mrq.data = &data;

    cmd.opcode = MMC_LOCK_UNLOCK;
    cmd.arg = 0;
    cmd.flags = MMC_RSP_R1B | MMC_CMD_ADTC;

    data.blksz = 512;
    data.blocks = 1;
    data.flags = MMC_DATA_WRITE;
    data.sg = &sg;
    data.sg_len = 1;
#if 0
    /* data.flags must already be set before doing this. */
    mmc_set_data_timeout(&data, card);
    if ((cmd.flags & MMC_RSP_R1B) == MMC_RSP_R1B) {
            /*
             * Pretend this is a data transfer and rely on the
             * host driver to compute timeout.  When all host
             * drivers support cmd.cmd_timeout for R1B, this
             * can be changed to:
             *
             *     mrq.data = NULL;
             *     cmd.cmd_timeout = idata->ic.cmd_timeout_ms;
             */
            cmd.cmd_timeout_ms = 100;
            data.timeout_ns = 1000 * cmd.cmd_timeout_ms * 1000000;
        }
#endif 
    tmp_buf = (u8 *)kmalloc(512, GFP_KERNEL);
    if (NULL == tmp_buf)
    {
        goto err_exit;
    }

    tmp_buf[0] |= mode;
    if (mode != SD_FORCE_ERASE)
    {
        tmp_buf[1] = pst_mmc_pwd->len;
        memcpy(tmp_buf+2, pst_mmc_pwd->ppwd, pst_mmc_pwd->len);
        tmp_buf[pst_mmc_pwd->len + 2] = '\0';
    }
    else
    {
        tmp_buf[1] = '\0';
    }
    sg_init_one(&sg, tmp_buf, 512);
    printk("mmc_send_cmd42():tmp_buf=%s\n",tmp_buf+1);

    // Send CMD42 request
    mmc_wait_for_req(card->host, &mrq);
    kfree(tmp_buf);
    if (cmd.error)
    {
		err = cmd.error;
        goto err_exit;
    }
    if (data.error)
    {
		err = data.error;
        goto err_exit;
    }
    /* TODO: here need to synchronize card status after send request.
     * reason: mmc_wait_for_req() return card status represent last commond excute result.
     */
#if 1
    if (cmd.resp[0] & R1_LOCK_UNLOCK_FAILED)
    {
        err = cmd.resp[0];
        goto err_exit;
    }
    else if (cmd.resp[0] & R1_CARD_IS_LOCKED && mode != SD_LOCK_PWD)
    {
        err = cmd.resp[0];
        goto err_exit;
    }
#elif 0
    ssleep(3);
    err = mmc_send_status(card, &status);     // to get mmc_wait_for_req() result.
    if (err)
    {
        printk("get mmc_wait_for_req() result error\n");
        goto err_exit;
    }
    if (status & R1_LOCK_UNLOCK_FAILED)
    {
        printk("operation error 0x%08x\n",status);
		err = status;
        goto err_exit;
    }
    else if (mode != SD_LOCK_PWD && (status&R1_CARD_IS_LOCKED))
    {
		err = status;
        goto err_exit;
    }

	/* set timeout for forced erase operation. (see MMC spec) */
    memset(&cmd, 0, sizeof(struct mmc_command));
 	cmd.opcode = MMC_SEND_STATUS;
 	cmd.arg = card->rca << 16;
 	cmd.flags = MMC_RSP_R1 | MMC_CMD_AC;
	fe_timeout = jiffies + 20 * HZ;
	do {
		err = mmc_wait_for_cmd(card->host, &cmd, 0);
		if (err)
			break;
        if (!(mode & SD_LOCK_PWD))
            continue;
        printk("mmc_send_cmd42():cmd.resp[0]=0x%08x\n",cmd.resp[0]);
		if (time_after(jiffies, fe_timeout) &&
		    !(cmd.resp[0] & R1_READY_FOR_DATA)) 
		{
			printk("forced erase timed out\n");
			err = -ETIMEDOUT;
			break;
		}
	} while (!(cmd.resp[0] & R1_READY_FOR_DATA));
#endif
    err = mmc_set_pwd(mode, pst_mmc_pwd);
    if (err)
    {
        goto err_exit;
    }
    
    if(g_stlockattr.init_status)
    {
        mmc_release_host(card->host);
    }
    
    return 0;

err_exit:
    if(g_stlockattr.init_status)
    {
        mmc_release_host(card->host);
    }
    return err;
}

int mmc_card_set_pwd(struct      mmc_pwd *pst_mmc_pwd)
{
    int err = -1;

    if (NULL == g_hi_host->mmc->card)
    {
        return err;
    }
    
    err = mmc_send_cmd42(g_hi_host->mmc->card, g_stlockattr.user_op, pst_mmc_pwd);
    if(err)
    {   
        printk("\033[40;32mSet password failed\033[0m\n");
        return err;
    }
    printk("\033[40;32mPassword set %s. Card will be locked when hardware reset\033[0m\n",g_pwd_store.stpwd.ppwd);

    return err;
}
EXPORT_SYMBOL(mmc_card_set_pwd);

int mmc_card_clr_pwd(struct      mmc_pwd *pst_mmc_pwd)
{
    int err = -1;

    g_stlockattr.user_op = SD_CLEAR_PWD;
    //printk("====== mmc_card_clr_pwd():g_stlockattr.init_status=%d ======",g_stlockattr.init_status);
    if (g_stlockattr.init_status && g_hi_host->mmc->card != NULL)
    {
        err = mmc_send_cmd42(g_hi_host->mmc->card, g_stlockattr.user_op, pst_mmc_pwd);
        if (err)
        {   
            printk("\033[40;32mClear password failed\033[0m\n");
            goto err_exit;
        }
        g_stlockattr.card_status = SD_UNLOCKED;
        printk("\033[40;32mPassword has cleared\033[0m\n");
    }
    else
    {
        init_completion(&mmc_lock_comp);
        mmc_save_pwd_tmp(&g_pwd_store.temp_pwd, pst_mmc_pwd);
        mmc_detect_change(g_hi_host->mmc, 0);     
        // TODO: here need sync with mmc_sd_init_card()
        wait_for_completion(&mmc_lock_comp);
    }
    g_stlockattr.user_op = SD_UNLOCK_PWD;  // restore default
    
    return 0;
err_exit:
    g_stlockattr.user_op = SD_UNLOCK_PWD;
    return err;
}
EXPORT_SYMBOL(mmc_card_clr_pwd);

int mmc_lock_card(struct    mmc_pwd *pst_mmc_pwd)
{
    int err = -1;
    
    g_stlockattr.user_op = SD_LOCK_PWD;
    if (g_hi_host->mmc->card != NULL)
    {
        err = mmc_send_cmd42(g_hi_host->mmc->card, g_stlockattr.user_op, pst_mmc_pwd);
        if(err)
        {   
            printk("\033[40;32mPassword lock failed\033[0m\n");
            return err;
        }
        g_stlockattr.card_status = SD_LOCKED;
        printk("\033[40;32mCard is locked\033[0m\n");
    }
    else
    {
        printk("\033[40;32mNone Card\033[0m\n");
        return err;
    }

    return 0;
}
EXPORT_SYMBOL(mmc_lock_card);

int mmc_unlock_card(struct      mmc_pwd *pst_mmc_pwd)
{
    int err = -1;
    
    g_stlockattr.user_op = SD_UNLOCK_PWD;
    if (g_stlockattr.init_status && g_hi_host->mmc->card != NULL)
    {
        err = mmc_send_cmd42(g_hi_host->mmc->card, g_stlockattr.user_op, pst_mmc_pwd);
        if(err)
        {   
            printk("\033[40;32mPassword unlock failed\033[0m\n");
            return err;
        }
        g_stlockattr.card_status = SD_UNLOCKED;
        printk("\033[40;32mPassword unlock success\033[0m\n");
    }
    else
    {
        init_completion(&mmc_lock_comp);
        mmc_save_pwd_tmp(&g_pwd_store.temp_pwd, pst_mmc_pwd);
        mmc_detect_change(g_hi_host->mmc, 0);
        // TODO: here need sync with mmc_sd_init_card()
        wait_for_completion(&mmc_lock_comp);
    }

    return 0;
}
EXPORT_SYMBOL(mmc_unlock_card);

int mmc_card_fe(void)
{
    int err;
    
    g_stlockattr.user_op = SD_FORCE_ERASE;
    if (g_stlockattr.init_status && g_hi_host->mmc->card != NULL)
    {
        err = mmc_send_cmd42(g_hi_host->mmc->card, g_stlockattr.user_op, NULL);
        if(err)
        {   
            printk("\033[40;32mCard password force erase failed\033[0m\n");
            goto err_exit;
        }    
        g_stlockattr.card_status = SD_UNLOCKED;
        printk("\033[40;32mCard password is erased\033[0m\n");
    }
    else
    {
        init_completion(&mmc_lock_comp);
        mmc_detect_change(g_hi_host->mmc, 0);
        // TODO: here need sync with mmc_sd_init_card()
        wait_for_completion(&mmc_lock_comp);
    }
    g_stlockattr.user_op = SD_UNLOCK_PWD;  // restore default
    
    return 0;
err_exit:
    g_stlockattr.user_op = SD_UNLOCK_PWD;
    return err;
}
EXPORT_SYMBOL(mmc_card_fe);

/* You can get only lock/unlock status if card init failed*/
int mmc_card_send_status(unsigned int *status)
{
    int err;

    if (g_stlockattr.init_status && g_hi_host->mmc->card != NULL)
    {
        mmc_claim_host(g_hi_host->mmc);
        err = mmc_send_status(g_hi_host->mmc->card, status);     // to get mmc_wait_for_req() result.
        mmc_release_host(g_hi_host->mmc);
        if (err)
        {
            printk("get mmc_wait_for_req() result error.\n");
            return err;
        }
    }
    else
    {
        *status = g_stlockattr.card_status << SD_LOCK_STATUS_SHIFT;
    }

    return 0;
}
EXPORT_SYMBOL(mmc_card_send_status);

static int _mmc_select_card(struct mmc_host *host, struct mmc_card *card)
{
	int err;
	struct mmc_command cmd = {0};

	BUG_ON(!host);

	cmd.opcode = MMC_SELECT_CARD;

	if (card) {
		cmd.arg = card->rca << 16;
		cmd.flags = MMC_RSP_R1 | MMC_CMD_AC;
	} else {
		cmd.arg = 0;
		cmd.flags = MMC_RSP_NONE | MMC_CMD_AC;
	}

	err = mmc_wait_for_cmd(host, &cmd, MMC_CMD_RETRIES);
	if (err)
		return err;

	return 0;
}

int mmc_select_card(struct mmc_card *card)
{
	BUG_ON(!card);

	return _mmc_select_card(card->host, card);
}

int mmc_deselect_cards(struct mmc_host *host)
{
	return _mmc_select_card(host, NULL);
}

int mmc_card_sleepawake(struct mmc_host *host, int sleep)
{
	struct mmc_command cmd = {0};
	struct mmc_card *card = host->card;
	int err;

	if (sleep)
		mmc_deselect_cards(host);

	cmd.opcode = MMC_SLEEP_AWAKE;
	cmd.arg = card->rca << 16;
	if (sleep)
		cmd.arg |= 1 << 15;

	cmd.flags = MMC_RSP_R1B | MMC_CMD_AC;
	err = mmc_wait_for_cmd(host, &cmd, 0);
	if (err)
		return err;

	/*
	 * If the host does not wait while the card signals busy, then we will
	 * will have to wait the sleep/awake timeout.  Note, we cannot use the
	 * SEND_STATUS command to poll the status because that command (and most
	 * others) is invalid while the card sleeps.
	 */
	if (!(host->caps & MMC_CAP_WAIT_WHILE_BUSY))
		mmc_delay(DIV_ROUND_UP(card->ext_csd.sa_timeout, 10000));

	if (!sleep)
		err = mmc_select_card(card);

	return err;
}

int mmc_go_idle(struct mmc_host *host)
{
	int err;
	struct mmc_command cmd = {0};

	/*
	 * Non-SPI hosts need to prevent chipselect going active during
	 * GO_IDLE; that would put chips into SPI mode.  Remind them of
	 * that in case of hardware that won't pull up DAT3/nCS otherwise.
	 *
	 * SPI hosts ignore ios.chip_select; it's managed according to
	 * rules that must accommodate non-MMC slaves which this layer
	 * won't even know about.
	 */
	if (!mmc_host_is_spi(host)) {
		mmc_set_chip_select(host, MMC_CS_HIGH);
		mmc_delay(1);
	}

	cmd.opcode = MMC_GO_IDLE_STATE;
	cmd.arg = 0;
	cmd.flags = MMC_RSP_SPI_R1 | MMC_RSP_NONE | MMC_CMD_BC;

	err = mmc_wait_for_cmd(host, &cmd, 0);

	mmc_delay(1);

	if (!mmc_host_is_spi(host)) {
		mmc_set_chip_select(host, MMC_CS_DONTCARE);
		mmc_delay(1);
	}

	host->use_spi_crc = 0;

	return err;
}

int mmc_send_op_cond(struct mmc_host *host, u32 ocr, u32 *rocr)
{
	struct mmc_command cmd = {0};
	int i, err = 0;

	BUG_ON(!host);

	cmd.opcode = MMC_SEND_OP_COND;
	cmd.arg = mmc_host_is_spi(host) ? 0 : ocr;
	cmd.flags = MMC_RSP_SPI_R1 | MMC_RSP_R3 | MMC_CMD_BCR;

	for (i = 100; i; i--) {
		err = mmc_wait_for_cmd(host, &cmd, 0);
		if (err)
			break;

		/* if we're just probing, do a single pass */
		if (ocr == 0)
			break;

		/* otherwise wait until reset completes */
		if (mmc_host_is_spi(host)) {
			if (!(cmd.resp[0] & R1_SPI_IDLE))
				break;
		} else {
			if (cmd.resp[0] & MMC_CARD_BUSY)
				break;
		}

		err = -ETIMEDOUT;

		mmc_delay(10);
	}

	if (rocr && !mmc_host_is_spi(host))
		*rocr = cmd.resp[0];

	return err;
}

int mmc_all_send_cid(struct mmc_host *host, u32 *cid)
{
	int err;
	struct mmc_command cmd = {0};

	BUG_ON(!host);
	BUG_ON(!cid);

	cmd.opcode = MMC_ALL_SEND_CID;
	cmd.arg = 0;
	cmd.flags = MMC_RSP_R2 | MMC_CMD_BCR;

	err = mmc_wait_for_cmd(host, &cmd, MMC_CMD_RETRIES);
	if (err)
		return err;

	memcpy(cid, cmd.resp, sizeof(u32) * 4);

	return 0;
}

int mmc_set_relative_addr(struct mmc_card *card)
{
	int err;
	struct mmc_command cmd = {0};

	BUG_ON(!card);
	BUG_ON(!card->host);

	cmd.opcode = MMC_SET_RELATIVE_ADDR;
	cmd.arg = card->rca << 16;
	cmd.flags = MMC_RSP_R1 | MMC_CMD_AC;

	err = mmc_wait_for_cmd(card->host, &cmd, MMC_CMD_RETRIES);
	if (err)
		return err;

	return 0;
}

static int
mmc_send_cxd_native(struct mmc_host *host, u32 arg, u32 *cxd, int opcode)
{
	int err;
	struct mmc_command cmd = {0};

	BUG_ON(!host);
	BUG_ON(!cxd);

	cmd.opcode = opcode;
	cmd.arg = arg;
	cmd.flags = MMC_RSP_R2 | MMC_CMD_AC;

	err = mmc_wait_for_cmd(host, &cmd, MMC_CMD_RETRIES);
	if (err)
		return err;

	memcpy(cxd, cmd.resp, sizeof(u32) * 4);

	return 0;
}

static int
mmc_send_cxd_data(struct mmc_card *card, struct mmc_host *host,
		u32 opcode, void *buf, unsigned len)
{
	struct mmc_request mrq = {NULL};
	struct mmc_command cmd = {0};
	struct mmc_data data = {0};
	struct scatterlist sg;
	void *data_buf;

	/* dma onto stack is unsafe/nonportable, but callers to this
	 * routine normally provide temporary on-stack buffers ...
	 */
	data_buf = kmalloc(len, GFP_KERNEL);
	if (data_buf == NULL)
		return -ENOMEM;

	mrq.cmd = &cmd;
	mrq.data = &data;

	cmd.opcode = opcode;
	cmd.arg = 0;

	/* NOTE HACK:  the MMC_RSP_SPI_R1 is always correct here, but we
	 * rely on callers to never use this with "native" calls for reading
	 * CSD or CID.  Native versions of those commands use the R2 type,
	 * not R1 plus a data block.
	 */
	cmd.flags = MMC_RSP_SPI_R1 | MMC_RSP_R1 | MMC_CMD_ADTC;

	data.blksz = len;
	data.blocks = 1;
	data.flags = MMC_DATA_READ;
	data.sg = &sg;
	data.sg_len = 1;

	sg_init_one(&sg, data_buf, len);

	if (opcode == MMC_SEND_CSD || opcode == MMC_SEND_CID) {
		/*
		 * The spec states that CSR and CID accesses have a timeout
		 * of 64 clock cycles.
		 */
		data.timeout_ns = 0;
		data.timeout_clks = 64;
	} else
		mmc_set_data_timeout(&data, card);

	mmc_wait_for_req(host, &mrq);

	memcpy(buf, data_buf, len);
	kfree(data_buf);

	if (cmd.error)
		return cmd.error;
	if (data.error)
		return data.error;

	return 0;
}

int mmc_send_csd(struct mmc_card *card, u32 *csd)
{
	int ret, i;

	if (!mmc_host_is_spi(card->host))
		return mmc_send_cxd_native(card->host, card->rca << 16,
				csd, MMC_SEND_CSD);

	ret = mmc_send_cxd_data(card, card->host, MMC_SEND_CSD, csd, 16);
	if (ret)
		return ret;

	for (i = 0;i < 4;i++)
		csd[i] = be32_to_cpu(csd[i]);

	return 0;
}

int mmc_send_cid(struct mmc_host *host, u32 *cid)
{
	int ret, i;

	if (!mmc_host_is_spi(host)) {
		if (!host->card)
			return -EINVAL;
		return mmc_send_cxd_native(host, host->card->rca << 16,
				cid, MMC_SEND_CID);
	}

	ret = mmc_send_cxd_data(NULL, host, MMC_SEND_CID, cid, 16);
	if (ret)
		return ret;

	for (i = 0;i < 4;i++)
		cid[i] = be32_to_cpu(cid[i]);

	return 0;
}

int mmc_send_ext_csd(struct mmc_card *card, u8 *ext_csd)
{
	return mmc_send_cxd_data(card, card->host, MMC_SEND_EXT_CSD,
			ext_csd, 512);
}

int mmc_spi_read_ocr(struct mmc_host *host, int highcap, u32 *ocrp)
{
	struct mmc_command cmd = {0};
	int err;

	cmd.opcode = MMC_SPI_READ_OCR;
	cmd.arg = highcap ? (1 << 30) : 0;
	cmd.flags = MMC_RSP_SPI_R3;

	err = mmc_wait_for_cmd(host, &cmd, 0);

	*ocrp = cmd.resp[1];
	return err;
}

int mmc_spi_set_crc(struct mmc_host *host, int use_crc)
{
	struct mmc_command cmd = {0};
	int err;

	cmd.opcode = MMC_SPI_CRC_ON_OFF;
	cmd.flags = MMC_RSP_SPI_R1;
	cmd.arg = use_crc;

	err = mmc_wait_for_cmd(host, &cmd, 0);
	if (!err)
		host->use_spi_crc = use_crc;
	return err;
}

/**
 *	mmc_switch - modify EXT_CSD register
 *	@card: the MMC card associated with the data transfer
 *	@set: cmd set values
 *	@index: EXT_CSD register index
 *	@value: value to program into EXT_CSD register
 *	@timeout_ms: timeout (ms) for operation performed by register write,
 *                   timeout of zero implies maximum possible timeout
 *
 *	Modifies the EXT_CSD register for selected card.
 */
int mmc_switch(struct mmc_card *card, u8 set, u8 index, u8 value,
	       unsigned int timeout_ms)
{
	int err;
	struct mmc_command cmd = {0};
	u32 status;

	BUG_ON(!card);
	BUG_ON(!card->host);

	cmd.opcode = MMC_SWITCH;
	cmd.arg = (MMC_SWITCH_MODE_WRITE_BYTE << 24) |
		  (index << 16) |
		  (value << 8) |
		  set;
	cmd.flags = MMC_RSP_SPI_R1B | MMC_RSP_R1B | MMC_CMD_AC;
	cmd.cmd_timeout_ms = timeout_ms;

	err = mmc_wait_for_cmd(card->host, &cmd, MMC_CMD_RETRIES);
	if (err)
		return err;

	/* Must check status to be sure of no errors */
	do {
		err = mmc_send_status(card, &status);
		if (err)
			return err;
		if (card->host->caps & MMC_CAP_WAIT_WHILE_BUSY)
			break;
		if (mmc_host_is_spi(card->host))
			break;
	} while (R1_CURRENT_STATE(status) == R1_STATE_PRG);

	if (mmc_host_is_spi(card->host)) {
		if (status & R1_SPI_ILLEGAL_COMMAND)
			return -EBADMSG;
	} else {
		if (status & 0xFDFFA000)
			pr_warning("%s: unexpected status %#x after "
			       "switch", mmc_hostname(card->host), status);
		if (status & R1_SWITCH_ERROR)
			return -EBADMSG;
	}

	return 0;
}
EXPORT_SYMBOL_GPL(mmc_switch);

int mmc_send_status(struct mmc_card *card, u32 *status)
{
	int err;
	struct mmc_command cmd = {0};

	BUG_ON(!card);
	BUG_ON(!card->host);

	cmd.opcode = MMC_SEND_STATUS;
	if (!mmc_host_is_spi(card->host))
		cmd.arg = card->rca << 16;
	cmd.flags = MMC_RSP_SPI_R2 | MMC_RSP_R1 | MMC_CMD_AC;

	err = mmc_wait_for_cmd(card->host, &cmd, MMC_CMD_RETRIES);
	if (err)
		return err;

	/* NOTE: callers are required to understand the difference
	 * between "native" and SPI format status words!
	 */
	if (status)
		*status = cmd.resp[0];

	return 0;
}

static int
mmc_send_bus_test(struct mmc_card *card, struct mmc_host *host, u8 opcode,
		  u8 len)
{
	struct mmc_request mrq = {NULL};
	struct mmc_command cmd = {0};
	struct mmc_data data = {0};
	struct scatterlist sg;
	u8 *data_buf;
	u8 *test_buf;
	int i, err;
	static u8 testdata_8bit[8] = { 0x55, 0xaa, 0, 0, 0, 0, 0, 0 };
	static u8 testdata_4bit[4] = { 0x5a, 0, 0, 0 };

	/* dma onto stack is unsafe/nonportable, but callers to this
	 * routine normally provide temporary on-stack buffers ...
	 */
	data_buf = kmalloc(len, GFP_KERNEL);
	if (!data_buf)
		return -ENOMEM;

	if (len == 8)
		test_buf = testdata_8bit;
	else if (len == 4)
		test_buf = testdata_4bit;
	else {
		pr_err("%s: Invalid bus_width %d\n",
		       mmc_hostname(host), len);
		kfree(data_buf);
		return -EINVAL;
	}

	if (opcode == MMC_BUS_TEST_W)
		memcpy(data_buf, test_buf, len);

	mrq.cmd = &cmd;
	mrq.data = &data;
	cmd.opcode = opcode;
	cmd.arg = 0;

	/* NOTE HACK:  the MMC_RSP_SPI_R1 is always correct here, but we
	 * rely on callers to never use this with "native" calls for reading
	 * CSD or CID.  Native versions of those commands use the R2 type,
	 * not R1 plus a data block.
	 */
	cmd.flags = MMC_RSP_SPI_R1 | MMC_RSP_R1 | MMC_CMD_ADTC;

	data.blksz = len;
	data.blocks = 1;
	if (opcode == MMC_BUS_TEST_R)
		data.flags = MMC_DATA_READ;
	else
		data.flags = MMC_DATA_WRITE;

	data.sg = &sg;
	data.sg_len = 1;
	sg_init_one(&sg, data_buf, len);
	mmc_wait_for_req(host, &mrq);
	err = 0;
	if (opcode == MMC_BUS_TEST_R) {
		for (i = 0; i < len / 4; i++)
			if ((test_buf[i] ^ data_buf[i]) != 0xff) {
				err = -EIO;
				break;
			}
	}
	kfree(data_buf);

	if (cmd.error)
		return cmd.error;
	if (data.error)
		return data.error;

	return err;
}

int mmc_bus_test(struct mmc_card *card, u8 bus_width)
{
	int err, width;

	if (bus_width == MMC_BUS_WIDTH_8)
		width = 8;
	else if (bus_width == MMC_BUS_WIDTH_4)
		width = 4;
	else if (bus_width == MMC_BUS_WIDTH_1)
		return 0; /* no need for test */
	else
		return -EINVAL;

	/*
	 * Ignore errors from BUS_TEST_W.  BUS_TEST_R will fail if there
	 * is a problem.  This improves chances that the test will work.
	 */
	mmc_send_bus_test(card, card->host, MMC_BUS_TEST_W, width);
	err = mmc_send_bus_test(card, card->host, MMC_BUS_TEST_R, width);
	return err;
}

int mmc_send_hpi_cmd(struct mmc_card *card, u32 *status)
{
	struct mmc_command cmd = {0};
	unsigned int opcode;
	int err;

	if (!card->ext_csd.hpi) {
		pr_warning("%s: Card didn't support HPI command\n",
			   mmc_hostname(card->host));
		return -EINVAL;
	}

	opcode = card->ext_csd.hpi_cmd;
	if (opcode == MMC_STOP_TRANSMISSION)
		cmd.flags = MMC_RSP_R1B | MMC_CMD_AC;
	else if (opcode == MMC_SEND_STATUS)
		cmd.flags = MMC_RSP_R1 | MMC_CMD_AC;

	cmd.opcode = opcode;
	cmd.arg = card->rca << 16 | 1;
	cmd.cmd_timeout_ms = card->ext_csd.out_of_int_time;

	err = mmc_wait_for_cmd(card->host, &cmd, 0);
	if (err) {
		pr_warn("%s: error %d interrupting operation. "
			"HPI command response %#x\n", mmc_hostname(card->host),
			err, cmd.resp[0]);
		return err;
	}
	if (status)
		*status = cmd.resp[0];

	return 0;
}
