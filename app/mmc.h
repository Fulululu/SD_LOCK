/*
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public
 * License v2 as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public
 * License along with this program; if not, write to the
 * Free Software Foundation, Inc., 59 Temple Place - Suite 330,
 * Boston, MA 021110-1307, USA.
 *
 * Modified to add field firmware update support,
 * those modifications are Copyright (c) 2016 SanDisk Corp.
 */


/* From kernel linux/major.h */
#define MMC_BLOCK_MAJOR			179

/* From kernel linux/mmc/mmc.h */
/* Standard MMC commands (4.1)           type  argument     response */
   /* class 1 */
#define MMC_GO_IDLE_STATE         0   /* bc                          */
#define MMC_SEND_OP_COND          1   /* bcr  [31:0] OCR         R3  */
#define MMC_ALL_SEND_CID          2   /* bcr                     R2  */
#define MMC_SET_RELATIVE_ADDR     3   /* ac   [31:16] RCA        R1  */
#define MMC_SET_DSR               4   /* bc   [31:16] RCA            */
#define MMC_SLEEP_AWAKE		  5   /* ac   [31:16] RCA 15:flg R1b */
#define MMC_SWITCH                6   /* ac   [31:0] See below   R1b */
#define MMC_SELECT_CARD           7   /* ac   [31:16] RCA        R1  */
#define MMC_SEND_EXT_CSD          8   /* adtc                    R1  */
#define MMC_SEND_CSD              9   /* ac   [31:16] RCA        R2  */
#define MMC_SEND_CID             10   /* ac   [31:16] RCA        R2  */
#define MMC_READ_DAT_UNTIL_STOP  11   /* adtc [31:0] dadr        R1  */
#define MMC_STOP_TRANSMISSION    12   /* ac                      R1b */
#define MMC_SEND_STATUS          13   /* ac   [31:16] RCA        R1  */
#define MMC_BUS_TEST_R           14   /* adtc                    R1  */
#define MMC_GO_INACTIVE_STATE    15   /* ac   [31:16] RCA            */
#define MMC_BUS_TEST_W           19   /* adtc                    R1  */
#define MMC_SPI_READ_OCR         58   /* spi                  spi_R3 */
#define MMC_SPI_CRC_ON_OFF       59   /* spi  [0:0] flag      spi_R1 */

  /* class 2 */
#define MMC_SET_BLOCKLEN         16   /* ac   [31:0] block len   R1  */
#define MMC_READ_SINGLE_BLOCK    17   /* adtc [31:0] data addr   R1  */
#define MMC_READ_MULTIPLE_BLOCK  18   /* adtc [31:0] data addr   R1  */
#define MMC_SEND_TUNING_BLOCK    19   /* adtc                    R1  */
#define MMC_SEND_TUNING_BLOCK_HS200	21	/* adtc R1  */

  /* class 3 */
#define MMC_WRITE_DAT_UNTIL_STOP 20   /* adtc [31:0] data addr   R1  */

  /* class 4 */
#define MMC_SET_BLOCK_COUNT      23   /* adtc [31:0] data addr   R1  */
#define MMC_WRITE_BLOCK          24   /* adtc [31:0] data addr   R1  */
#define MMC_WRITE_MULTIPLE_BLOCK 25   /* adtc                    R1  */
#define MMC_PROGRAM_CID          26   /* adtc                    R1  */
#define MMC_PROGRAM_CSD          27   /* adtc                    R1  */

  /* class 6 */
#define MMC_SET_WRITE_PROT       28   /* ac   [31:0] data addr   R1b */
#define MMC_CLR_WRITE_PROT       29   /* ac   [31:0] data addr   R1b */
#define MMC_SEND_WRITE_PROT      30   /* adtc [31:0] wpdata addr R1  */

  /* class 5 */
#define MMC_ERASE_GROUP_START    35   /* ac   [31:0] data addr   R1  */
#define MMC_ERASE_GROUP_END      36   /* ac   [31:0] data addr   R1  */
#define MMC_ERASE                38   /* ac                      R1b */

  /* class 9 */
#define MMC_FAST_IO              39   /* ac   <Complex>          R4  */
#define MMC_GO_IRQ_STATE         40   /* bcr                     R5  */

  /* class 7 */
#define MMC_LOCK_UNLOCK          42   /* adtc                    R1b */

  /* class 8 */
#define MMC_APP_CMD              55   /* ac   [31:16] RCA        R1  */
#define MMC_GEN_CMD              56   /* adtc [0] RD/WR          R1  */

/*
 * EXT_CSD fields
 */
#define EXT_CSD_S_CMD_SET		504
#define EXT_CSD_HPI_FEATURE		503
#define EXT_CSD_BKOPS_SUPPORT		502	/* RO */
#define EXT_CSD_SUPPORTED_MODES		493	/* RO */
#define EXT_CSD_FFU_FEATURES		492	/* RO */
#define EXT_CSD_FFU_ARG_3		490	/* RO */
#define EXT_CSD_FFU_ARG_2		489	/* RO */
#define EXT_CSD_FFU_ARG_1		488	/* RO */
#define EXT_CSD_FFU_ARG_0		487	/* RO */
#define EXT_CSD_CMDQ_DEPTH		307	/* RO */
#define EXT_CSD_CMDQ_SUPPORT		308	/* RO */
#define EXT_CSD_NUM_OF_FW_SEC_PROG_3	305	/* RO */
#define EXT_CSD_NUM_OF_FW_SEC_PROG_2	304	/* RO */
#define EXT_CSD_NUM_OF_FW_SEC_PROG_1	303	/* RO */
#define EXT_CSD_NUM_OF_FW_SEC_PROG_0	302	/* RO */
#define EXT_CSD_DEVICE_LIFE_TIME_EST_TYP_B 	269	/* RO */
#define EXT_CSD_DEVICE_LIFE_TIME_EST_TYP_A 	268	/* RO */
#define EXT_CSD_PRE_EOL_INFO		267	/* RO */
#define EXT_CSD_FIRMWARE_VERSION	254	/* RO */
#define EXT_CSD_CACHE_SIZE_3		252
#define EXT_CSD_CACHE_SIZE_2		251
#define EXT_CSD_CACHE_SIZE_1		250
#define EXT_CSD_CACHE_SIZE_0		249
#define EXT_CSD_BOOT_INFO		228	/* R/W */
#define EXT_CSD_HC_ERASE_GRP_SIZE	224
#define EXT_CSD_HC_WP_GRP_SIZE		221
#define EXT_CSD_SEC_COUNT_3		215
#define EXT_CSD_SEC_COUNT_2		214
#define EXT_CSD_SEC_COUNT_1		213
#define EXT_CSD_SEC_COUNT_0		212
#define EXT_CSD_PART_SWITCH_TIME	199
#define EXT_CSD_REV			192
#define EXT_CSD_BOOT_CFG		179
#define EXT_CSD_PART_CONFIG		179
#define EXT_CSD_BOOT_BUS_CONDITIONS	177
#define EXT_CSD_ERASE_GROUP_DEF		175
#define EXT_CSD_BOOT_WP			173
#define EXT_CSD_USER_WP			171
#define EXT_CSD_FW_CONFIG		169	/* R/W */
#define EXT_CSD_WR_REL_SET		167
#define EXT_CSD_WR_REL_PARAM		166
#define EXT_CSD_SANITIZE_START		165
#define EXT_CSD_BKOPS_EN		163	/* R/W */
#define EXT_CSD_RST_N_FUNCTION		162	/* R/W */
#define EXT_CSD_PARTITIONING_SUPPORT	160	/* RO */
#define EXT_CSD_MAX_ENH_SIZE_MULT_2	159
#define EXT_CSD_MAX_ENH_SIZE_MULT_1	158
#define EXT_CSD_MAX_ENH_SIZE_MULT_0	157
#define EXT_CSD_PARTITIONS_ATTRIBUTE	156	/* R/W */
#define EXT_CSD_PARTITION_SETTING_COMPLETED	155	/* R/W */
#define EXT_CSD_GP_SIZE_MULT_4_2	154
#define EXT_CSD_GP_SIZE_MULT_4_1	153
#define EXT_CSD_GP_SIZE_MULT_4_0	152
#define EXT_CSD_GP_SIZE_MULT_3_2	151
#define EXT_CSD_GP_SIZE_MULT_3_1	150
#define EXT_CSD_GP_SIZE_MULT_3_0	149
#define EXT_CSD_GP_SIZE_MULT_2_2	148
#define EXT_CSD_GP_SIZE_MULT_2_1	147
#define EXT_CSD_GP_SIZE_MULT_2_0	146
#define EXT_CSD_GP_SIZE_MULT_1_2	145
#define EXT_CSD_GP_SIZE_MULT_1_1	144
#define EXT_CSD_GP_SIZE_MULT_1_0	143
#define EXT_CSD_ENH_SIZE_MULT_2		142
#define EXT_CSD_ENH_SIZE_MULT_1		141
#define EXT_CSD_ENH_SIZE_MULT_0		140
#define EXT_CSD_ENH_START_ADDR_3	139
#define EXT_CSD_ENH_START_ADDR_2	138
#define EXT_CSD_ENH_START_ADDR_1	137
#define EXT_CSD_ENH_START_ADDR_0	136
#define EXT_CSD_NATIVE_SECTOR_SIZE	63 /* R */
#define EXT_CSD_USE_NATIVE_SECTOR	62 /* R/W */
#define EXT_CSD_DATA_SECTOR_SIZE	61 /* R */
#define EXT_CSD_EXT_PARTITIONS_ATTRIBUTE_1	53
#define EXT_CSD_EXT_PARTITIONS_ATTRIBUTE_0	52
#define EXT_CSD_CACHE_CTRL		33
#define EXT_CSD_MODE_CONFIG		30
#define EXT_CSD_MODE_OPERATION_CODES	29	/* W */
#define EXT_CSD_FFU_STATUS		26	/* R */
#define EXT_CSD_CMDQ_MODE_EN		15	/* R/W */

/*
 * WR_REL_PARAM field definitions
 */
#define HS_CTRL_REL	(1<<0)
#define EN_REL_WR	(1<<2)

/*
 * BKOPS_EN field definition
 */
#define BKOPS_ENABLE	(1<<0)

/*
 * EXT_CSD field definitions
 */
#define EXT_CSD_FFU_INSTALL		(0x01)
#define EXT_CSD_FFU_MODE		(0x01)
#define EXT_CSD_NORMAL_MODE		(0x00)
#define EXT_CSD_FFU			(1<<0)
#define EXT_CSD_UPDATE_DISABLE		(1<<0)
#define EXT_CSD_HPI_SUPP		(1<<0)
#define EXT_CSD_HPI_IMPL		(1<<1)
#define EXT_CSD_CMD_SET_NORMAL		(1<<0)
#define EXT_CSD_BOOT_WP_B_PWR_WP_DIS	(0x40)
#define EXT_CSD_BOOT_WP_B_PERM_WP_DIS	(0x10)
#define EXT_CSD_BOOT_WP_B_PERM_WP_EN	(0x04)
#define EXT_CSD_BOOT_WP_B_PWR_WP_EN	(0x01)
#define EXT_CSD_BOOT_INFO_HS_MODE	(1<<2)
#define EXT_CSD_BOOT_INFO_DDR_DDR	(1<<1)
#define EXT_CSD_BOOT_INFO_ALT		(1<<0)
#define EXT_CSD_BOOT_CFG_ACK		(1<<6)
#define EXT_CSD_BOOT_CFG_EN		(0x38)
#define EXT_CSD_BOOT_CFG_ACC		(0x07)
#define EXT_CSD_RST_N_EN_MASK		(0x03)
#define EXT_CSD_HW_RESET_EN		(0x01)
#define EXT_CSD_HW_RESET_DIS		(0x02)
#define EXT_CSD_PART_CONFIG_ACC_MASK	  (0x7)
#define EXT_CSD_PART_CONFIG_ACC_NONE	  (0x0)
#define EXT_CSD_PART_CONFIG_ACC_BOOT0	  (0x1)
#define EXT_CSD_PART_CONFIG_ACC_BOOT1	  (0x2)
#define EXT_CSD_PART_CONFIG_ACC_USER_AREA (0x7)
#define EXT_CSD_PART_CONFIG_ACC_ACK	  (0x40)
#define EXT_CSD_PARTITIONING_EN		(1<<0)
#define EXT_CSD_ENH_ATTRIBUTE_EN	(1<<1)
#define EXT_CSD_ENH_4			(1<<4)
#define EXT_CSD_ENH_3			(1<<3)
#define EXT_CSD_ENH_2			(1<<2)
#define EXT_CSD_ENH_1			(1<<1)
#define EXT_CSD_ENH_USR			(1<<0)
#define EXT_CSD_REV_V5_1		8
#define EXT_CSD_REV_V5_0		7
#define EXT_CSD_REV_V4_5		6
#define EXT_CSD_REV_V4_4_1		5
#define EXT_CSD_REV_V4_3		3
#define EXT_CSD_REV_V4_2		2
#define EXT_CSD_REV_V4_1		1
#define EXT_CSD_REV_V4_0		0


/* From kernel linux/mmc/core.h */
#define MMC_RSP_PRESENT	(1 << 0)
#define MMC_RSP_136	(1 << 1)		/* 136 bit response */
#define MMC_RSP_CRC	(1 << 2)		/* expect valid crc */
#define MMC_RSP_BUSY	(1 << 3)		/* card may send busy */
#define MMC_RSP_OPCODE	(1 << 4)		/* response contains opcode */

#define MMC_CMD_AC	(0 << 5)
#define MMC_CMD_ADTC	(1 << 5)

#define MMC_RSP_SPI_S1	(1 << 7)		/* one status byte */
#define MMC_RSP_SPI_BUSY (1 << 10)		/* card may send busy */

#define MMC_RSP_SPI_R1	(MMC_RSP_SPI_S1)
#define MMC_RSP_SPI_R1B	(MMC_RSP_SPI_S1|MMC_RSP_SPI_BUSY)

#define MMC_RSP_R1	(MMC_RSP_PRESENT|MMC_RSP_CRC|MMC_RSP_OPCODE)
#define MMC_RSP_R1B	(MMC_RSP_PRESENT|MMC_RSP_CRC|MMC_RSP_OPCODE|MMC_RSP_BUSY)