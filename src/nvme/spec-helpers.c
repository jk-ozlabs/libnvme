// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 * This file is part of libnvme.
 * Copyright (c) 2020 Western Digital Corporation or its affiliates.
 *
 * Authors: Keith Busch <keith.busch@wdc.com>
 * 	    Chaitanya Kulkarni <chaitanya.kulkarni@wdc.com>
 */

#include <string.h>
#include <errno.h>

#if 0
#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <dirent.h>
#include <libgen.h>

#include <sys/param.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <unistd.h>
#endif

#include "util.h"

static inline __u8 nvme_generic_status_to_errno(__u16 status)
{
	switch (status) {
	case NVME_SC_INVALID_OPCODE:
	case NVME_SC_INVALID_FIELD:
	case NVME_SC_INVALID_NS:
	case NVME_SC_SGL_INVALID_LAST:
	case NVME_SC_SGL_INVALID_COUNT:
	case NVME_SC_SGL_INVALID_DATA:
	case NVME_SC_SGL_INVALID_METADATA:
	case NVME_SC_SGL_INVALID_TYPE:
	case NVME_SC_SGL_INVALID_OFFSET:
		return EINVAL;
	case NVME_SC_CMDID_CONFLICT:
		return EADDRINUSE;
	case NVME_SC_DATA_XFER_ERROR:
	case NVME_SC_INTERNAL:
	case NVME_SC_SANITIZE_FAILED:
		return EIO;
	case NVME_SC_POWER_LOSS:
	case NVME_SC_ABORT_REQ:
	case NVME_SC_ABORT_QUEUE:
	case NVME_SC_FUSED_FAIL:
	case NVME_SC_FUSED_MISSING:
		return EWOULDBLOCK;
	case NVME_SC_CMD_SEQ_ERROR:
		return EILSEQ;
	case NVME_SC_SANITIZE_IN_PROGRESS:
		return EINPROGRESS;
	case NVME_SC_NS_WRITE_PROTECTED:
	case NVME_SC_NS_NOT_READY:
	case NVME_SC_RESERVATION_CONFLICT:
		return EACCES;
	case NVME_SC_LBA_RANGE:
		return EREMOTEIO;
	case NVME_SC_CAP_EXCEEDED:
		return ENOSPC;
	}
	return EIO;
}

static inline __u8 nvme_cmd_specific_status_to_errno(__u16 status)
{
	switch (status) {
	case NVME_SC_CQ_INVALID:
	case NVME_SC_QID_INVALID:
	case NVME_SC_QUEUE_SIZE:
	case NVME_SC_FIRMWARE_SLOT:
	case NVME_SC_FIRMWARE_IMAGE:
	case NVME_SC_INVALID_VECTOR:
	case NVME_SC_INVALID_LOG_PAGE:
	case NVME_SC_INVALID_FORMAT:
	case NVME_SC_INVALID_QUEUE:
	case NVME_SC_NS_INSUFFICIENT_CAP:
	case NVME_SC_NS_ID_UNAVAILABLE:
	case NVME_SC_CTRL_LIST_INVALID:
	case NVME_SC_BAD_ATTRIBUTES:
	case NVME_SC_INVALID_PI:
		return EINVAL;
	case NVME_SC_ABORT_LIMIT:
	case NVME_SC_ASYNC_LIMIT:
		return EDQUOT;
	case NVME_SC_FW_NEEDS_CONV_RESET:
	case NVME_SC_FW_NEEDS_SUBSYS_RESET:
	case NVME_SC_FW_NEEDS_MAX_TIME:
		return ERESTART;
	case NVME_SC_FEATURE_NOT_SAVEABLE:
	case NVME_SC_FEATURE_NOT_CHANGEABLE:
	case NVME_SC_FEATURE_NOT_PER_NS:
	case NVME_SC_FW_ACTIVATE_PROHIBITED:
	case NVME_SC_NS_IS_PRIVATE:
	case NVME_SC_BP_WRITE_PROHIBITED:
	case NVME_SC_READ_ONLY:
	case NVME_SC_PMR_SAN_PROHIBITED:
		return EPERM;
	case NVME_SC_OVERLAPPING_RANGE:
	case NVME_SC_NS_NOT_ATTACHED:
		return ENOSPC;
	case NVME_SC_NS_ALREADY_ATTACHED:
		return EALREADY;
	case NVME_SC_THIN_PROV_NOT_SUPP:
		return EOPNOTSUPP;
	}

	return EIO;
}

static inline __u8 nvme_fabrics_status_to_errno(__u16 status)
{
	switch (status) {
	case NVME_SC_CONNECT_FORMAT:
	case NVME_SC_CONNECT_INVALID_PARAM:
		return EINVAL;
	case NVME_SC_CONNECT_CTRL_BUSY:
		return EBUSY;
	case NVME_SC_CONNECT_RESTART_DISC:
		return ERESTART;
	case NVME_SC_CONNECT_INVALID_HOST:
		return ECONNREFUSED;
	case NVME_SC_DISCOVERY_RESTART:
		return EAGAIN;
	case NVME_SC_AUTH_REQUIRED:
		return EPERM;
	}

	return EIO;
}

__u8 nvme_status_to_errno(int status, bool fabrics)
{
	__u16 sc;

	if (!status)
		return 0;
	if (status < 0)
		return errno;

	sc = nvme_status_code(status);
	switch (nvme_status_code_type(status)) {
	case NVME_SCT_GENERIC:
		return nvme_generic_status_to_errno(sc);
	case NVME_SCT_CMD_SPECIFIC:
		if  (fabrics)
			return nvme_fabrics_status_to_errno(sc);
		return nvme_cmd_specific_status_to_errno(sc);
	default:
		return EIO;
	}
}

void nvme_init_copy_range(struct nvme_copy_range *copy, __u16 *nlbs,
			  __u64 *slbas, __u32 *eilbrts, __u32 *elbatms,
			  __u32 *elbats, __u16 nr)
{
	int i;

	for (i = 0; i < nr; i++) {
		copy[i].nlb = cpu_to_le16(nlbs[i]);
		copy[i].slba = cpu_to_le64(slbas[i]);
		copy[i].eilbrt = cpu_to_le32(eilbrts[i]);
		copy[i].elbatm = cpu_to_le16(elbatms[i]);
		copy[i].elbat = cpu_to_le16(elbats[i]);
	}
}

void nvme_init_dsm_range(struct nvme_dsm_range *dsm, __u32 *ctx_attrs,
			 __u32 *llbas, __u64 *slbas, __u16 nr_ranges)
{
	int i;

	for (i = 0; i < nr_ranges; i++) {
		dsm[i].cattr = cpu_to_le32(ctx_attrs[i]);
		dsm[i].nlb = cpu_to_le32(llbas[i]);
		dsm[i].slba = cpu_to_le64(slbas[i]);
	}
}

void nvme_init_id_ns(struct nvme_id_ns *ns, __u64 nsze, __u64 ncap, __u8 flbas,
		__u8 dps, __u8 nmic, __u32 anagrpid, __u16 nvmsetid)
{
	memset(ns, 0, sizeof(*ns));
	ns->nsze = cpu_to_le64(nsze);
	ns->ncap = cpu_to_le64(ncap);
	ns->flbas = flbas;
	ns->dps = dps;
	ns->nmic = nmic;
	ns->anagrpid = cpu_to_le32(anagrpid);
	ns->nvmsetid = cpu_to_le16(nvmsetid);
}

void nvme_init_ctrl_list(struct nvme_ctrl_list *cntlist, __u16 num_ctrls,
			  __u16 *ctrlist)
{
	int i;

	cntlist->num = cpu_to_le16(num_ctrls);
	for (i = 0; i < num_ctrls; i++)
		cntlist->identifier[i] = cpu_to_le16(ctrlist[i]);
}

int nvme_get_feature_length(int fid, __u32 cdw11, __u32 *len)
{
	switch (fid) {
	case NVME_FEAT_FID_LBA_RANGE:
		*len = sizeof(struct nvme_lba_range_type);
		break;
	case NVME_FEAT_FID_AUTO_PST:
		*len = sizeof(struct nvme_feat_auto_pst);
		break;
	case NVME_FEAT_FID_PLM_CONFIG:
		*len = sizeof(struct nvme_plm_config);
		break;
	case NVME_FEAT_FID_TIMESTAMP:
		*len = sizeof(struct nvme_timestamp);
		break;
	case NVME_FEAT_FID_HOST_BEHAVIOR:
		*len = sizeof(struct nvme_feat_host_behavior);
		break;
	case NVME_FEAT_FID_HOST_ID:
		*len = (cdw11 & 0x1) ? 16 : 8;
		break;
	case NVME_FEAT_FID_ARBITRATION:
	case NVME_FEAT_FID_POWER_MGMT:
	case NVME_FEAT_FID_TEMP_THRESH:
	case NVME_FEAT_FID_ERR_RECOVERY:
	case NVME_FEAT_FID_VOLATILE_WC:
	case NVME_FEAT_FID_NUM_QUEUES:
	case NVME_FEAT_FID_IRQ_COALESCE:
	case NVME_FEAT_FID_IRQ_CONFIG:
	case NVME_FEAT_FID_WRITE_ATOMIC:
	case NVME_FEAT_FID_ASYNC_EVENT:
	case NVME_FEAT_FID_HOST_MEM_BUF:
	case NVME_FEAT_FID_KATO:
	case NVME_FEAT_FID_HCTM:
	case NVME_FEAT_FID_NOPSC:
	case NVME_FEAT_FID_RRL:
	case NVME_FEAT_FID_PLM_WINDOW:
	case NVME_FEAT_FID_LBA_STS_INTERVAL:
	case NVME_FEAT_FID_SANITIZE:
	case NVME_FEAT_FID_ENDURANCE_EVT_CFG:
	case NVME_FEAT_FID_SW_PROGRESS:
	case NVME_FEAT_FID_RESV_MASK:
	case NVME_FEAT_FID_RESV_PERSIST:
	case NVME_FEAT_FID_WRITE_PROTECT:
		*len = 0;
		break;
	default:
		errno = EINVAL;
		return -1;
	}
	return 0;
}

int nvme_get_directive_receive_length(enum nvme_directive_dtype dtype,
		enum nvme_directive_receive_doper doper, __u32 *len)
{
	switch (dtype) {
	case NVME_DIRECTIVE_DTYPE_IDENTIFY:
		switch (doper) {
		case NVME_DIRECTIVE_RECEIVE_IDENTIFY_DOPER_PARAM:
			*len = sizeof(struct nvme_id_directives);
			return 0;
		default:
			errno = EINVAL;
			return -1;
		}
	case NVME_DIRECTIVE_DTYPE_STREAMS:
		switch (doper) {
		case NVME_DIRECTIVE_RECEIVE_STREAMS_DOPER_PARAM:
			*len = sizeof(struct nvme_streams_directive_params);
			return 0;
		case NVME_DIRECTIVE_RECEIVE_STREAMS_DOPER_STATUS:
			*len = (128 * 1024) * sizeof(__le16);
			return 0;
		case NVME_DIRECTIVE_RECEIVE_STREAMS_DOPER_RESOURCE:
			*len = 0;
			return 0;
		default:
			return -EINVAL;
		}
	default:
		return -EINVAL;
	}
}
