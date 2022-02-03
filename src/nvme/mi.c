// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 * This file is part of libnvme.
 * Copyright (c) 2021 Code Construct Pty Ltd
 *
 * Authors: Jeremy Kerr <jk@codeconstruct.com.au>
 */

#include <errno.h>
#include <stdlib.h>
#include <stdlib.h>

#include <ccan/endian/endian.h>

#include "log.h"
#include "mi.h"
#include "mi.h"
#include "private.h"

struct nvme_mi_ep *nvme_mi_init_ep(void)
{
	struct nvme_mi_ep *ep;

	ep = malloc(sizeof(*ep));
	/* no other inits, yet.. */

	return ep;
}

struct nvme_mi_ctrl *nvme_mi_init_ctrl(nvme_mi_ep_t ep, __u16 ctrl_id)
{
	struct nvme_mi_ctrl *ctrl;

	ctrl = malloc(sizeof(*ctrl));
	if (!ctrl)
		return NULL;

	ctrl->ep = ep;
	ctrl->id = ctrl_id;

	return ctrl;
}

static __u32 nvme_mi_crc32_update(__u32 crc, void *data, size_t len)
{
	int i;

	while (len--) {
		crc ^= *(unsigned char *)(data++);
		for (i = 0; i < 8; i++)
			crc = (crc >> 1) ^ ((crc & 1) ? 0x82F63B78 : 0);
	}
	return crc;
}

static void nvme_mi_calc_req_mic(struct nvme_mi_req *req)
{
	__u32 crc = 0xffffffff;

	crc = nvme_mi_crc32_update(crc, req->hdr, req->hdr_len);
	crc = nvme_mi_crc32_update(crc, req->data, req->data_len);

	req->mic = ~crc;
}

/* returns zero on correct MIC */
static int nvme_mi_verify_resp_mic(struct nvme_mi_resp *resp)
{
	__u32 crc = 0xffffffff;

	crc = nvme_mi_crc32_update(crc, resp->hdr, resp->hdr_len);
	crc = nvme_mi_crc32_update(crc, resp->data, resp->data_len);

	return resp->mic != ~crc;
}

int nvme_mi_submit(nvme_mi_ep_t ep, struct nvme_mi_req *req,
		   struct nvme_mi_resp *resp)
{
	int rc;

	if (ep->transport->mic_enabled)
		nvme_mi_calc_req_mic(req);

	rc = ep->transport->submit(ep, req, resp);
	if (rc) {
		nvme_msg(LOG_INFO, "transport failure\n");
		return rc;
	}

	if (ep->transport->mic_enabled) {
		rc = nvme_mi_verify_resp_mic(resp);
		if (rc) {
			nvme_msg(LOG_WARNING, "crc mismatch\n");
			return rc;
		}
	}

	return 0;
}

static void nvme_mi_admin_init_req(struct nvme_mi_req *req,
				   struct nvme_mi_admin_req_hdr *hdr,
				   __u16 ctrl_id, __u8 opcode)
{
	memset(req, 0, sizeof(*req));
	memset(hdr, 0, sizeof(*hdr));

	hdr->hdr.type = NVME_MI_MSGTYPE_NVME;
	hdr->hdr.nmp = (NVME_MI_ROR_REQ << 7) |
		(NVME_MI_MT_ADMIN << 3); /* we always use command slot 0 */
	hdr->opcode = opcode;
	hdr->ctrl_id = cpu_to_le16(ctrl_id);

	req->hdr = &hdr->hdr;
	req->hdr_len = sizeof(*hdr);
}

static void nvme_mi_admin_init_resp(struct nvme_mi_resp *resp,
				    struct nvme_mi_admin_resp_hdr *hdr)
{
	memset(resp, 0, sizeof(*resp));
	resp->hdr = &hdr->hdr;
	resp->hdr_len = sizeof(*hdr);
}

int nvme_mi_admin_xfer(nvme_mi_ctrl_t ctrl,
		       struct nvme_mi_admin_req_hdr *admin_req,
		       size_t req_data_size,
		       struct nvme_mi_admin_resp_hdr *admin_resp,
		       off_t resp_data_offset,
		       size_t *resp_data_size)
{
	struct nvme_mi_resp resp;
	struct nvme_mi_req req;
	int rc;

	if (*resp_data_size > 0xffffffff)
		return -EINVAL;
	if (resp_data_offset > 0xffffffff)
		return -EINVAL;

	admin_req->hdr.type = NVME_MI_MSGTYPE_NVME;
	admin_req->hdr.nmp = (NVME_MI_ROR_REQ << 7) |
				(NVME_MI_MT_ADMIN << 3);
	memset(&req, 0, sizeof(req));
	req.hdr = &admin_req->hdr;
	req.hdr_len = sizeof(*admin_req);
	req.data = admin_req + 1;
	req.data_len = req_data_size;

	nvme_mi_calc_req_mic(&req);

	memset(&resp, 0, sizeof(resp));
	resp.hdr = &admin_resp->hdr;
	resp.hdr_len = sizeof(*admin_resp);
	resp.data = admin_resp + 1;
	resp.data_len = *resp_data_size;

	/* limit the response size, specify offset */
	admin_req->flags = 0x3;
	admin_req->dlen = cpu_to_le32(resp.data_len & 0xffffffff);
	admin_req->doff = cpu_to_le32(resp_data_offset & 0xffffffff);

	rc = nvme_mi_submit(ctrl->ep, &req, &resp);
	if (rc)
		return rc;

	*resp_data_size = resp.data_len;

	return 0;
}

static int nvme_mi_admin_identify(nvme_mi_ctrl_t ctrl,
				  enum nvme_identify_cns cns,
				  __u16 cid, __u16 nsid, void *id,
				  off_t offset, size_t size)
{
	struct nvme_mi_admin_resp_hdr resp_hdr;
	struct nvme_mi_admin_req_hdr req_hdr;
	struct nvme_mi_resp resp;
	struct nvme_mi_req req;
	int rc;

	if (!size || size > 0xffffffff)
		return -EINVAL;

	nvme_mi_admin_init_req(&req, &req_hdr, ctrl->id, nvme_admin_identify);
	req_hdr.cdw10 = cpu_to_le16(cid) << 16 | cpu_to_le16(cns);
	req_hdr.cdw11 = cpu_to_le16(nsid);
	req_hdr.dlen = cpu_to_le32(size & 0xffffffff);
	req_hdr.flags = 0x1;
	if (offset) {
		req_hdr.flags |= 0x2;
		req_hdr.doff = offset;
	}

	nvme_mi_calc_req_mic(&req);

	nvme_mi_admin_init_resp(&resp, &resp_hdr);
	resp.data = id;
	resp.data_len = size;

	rc = nvme_mi_submit(ctrl->ep, &req, &resp);
	if (rc)
		return rc;

	/* check status, map to return value */

	return 0;
}

int nvme_mi_admin_identify_ctrl(nvme_mi_ctrl_t ctrl,
				struct nvme_id_ctrl *id)
{
	return nvme_mi_admin_identify(ctrl, NVME_IDENTIFY_CNS_CTRL,
				      0, 0, id, 0, sizeof(*id));
}

int nvme_mi_admin_identify_ctrl_partial(nvme_mi_ctrl_t ctrl,
					struct nvme_id_ctrl *id,
					off_t offset, size_t size)
{
	void *buf;

	if (offset > sizeof(*id))
		return -EINVAL;
	if (size > sizeof(*id))
		return -EINVAL;
	if (offset + size > sizeof(*id))
		return -EINVAL;

	buf = id;
	buf += offset;

	return nvme_mi_admin_identify(ctrl, NVME_IDENTIFY_CNS_CTRL,
				      0, 0, buf, offset, size);
}

int nvme_mi_admin_identify_ctrl_list(nvme_mi_ctrl_t ctrl,
				     struct nvme_ctrl_list *ctrllist)
{
	return nvme_mi_admin_identify(ctrl, NVME_IDENTIFY_CNS_CTRL_LIST,
					 0, 0, ctrllist, 0, sizeof(*ctrllist));
}

static int __nvme_mi_admin_get_log_page(nvme_mi_ctrl_t ctrl, __u32 nsid,
					__u8 log_id, bool rae, off_t offset,
					size_t size, void *data)
{
	struct nvme_mi_admin_resp_hdr resp_hdr;
	struct nvme_mi_admin_req_hdr req_hdr;
	struct nvme_mi_resp resp;
	struct nvme_mi_req req;
	__u32 ndw;
	__u64 off;
	int rc;

	/* we have to get a response within a MCTP message size... */
	if (!size || size > 0x8000 - 8 || size < 4)
		return -EINVAL;

	ndw = (size >> 2) - 1;
	off = offset;

	nvme_mi_admin_init_req(&req, &req_hdr, ctrl->id, nvme_admin_get_log_page);

	req_hdr.cdw1 = cpu_to_le32(nsid);
	req_hdr.cdw10 = cpu_to_le16(ndw & 0xffff) << 16 |
			(rae ? 1 : 0) << 15 |
			NVME_LOG_LSP_NONE << 8 |
			log_id;

	req_hdr.cdw11 = NVME_LOG_LSI_NONE << 16 |
			cpu_to_le16(ndw >> 16);

	req_hdr.cdw12 = cpu_to_le32(off & 0xffffffff);
	req_hdr.cdw13 = cpu_to_le32(off >> 32);
	req_hdr.flags = 0x1;
	req_hdr.dlen = cpu_to_le32(size & 0xffffffff);

	nvme_mi_calc_req_mic(&req);

	nvme_mi_admin_init_resp(&resp, &resp_hdr);
	resp.data = data;
	resp.data_len = size;

	rc = nvme_mi_submit(ctrl->ep, &req, &resp);
	if (rc)
		return rc;

	if (resp_hdr.status)
		return resp_hdr.status;

	return 0;
}

int nvme_mi_admin_get_log_page_nsid(nvme_mi_ctrl_t ctrl, __u32 nsid,
				    __u8 log_id, bool rae, off_t offset,
				    size_t size, void *data)
{
	off_t xfer_offset;
	size_t xfer_size;
	bool xfer_rae;
	int rc = 0;

	xfer_size = 4096;

	for (xfer_offset = 0; xfer_offset < size; xfer_offset += xfer_size) {

		/* retain unless we're the last transfer */
		if (xfer_offset + xfer_size >= size) {
			xfer_size = size - xfer_offset;
			xfer_rae = rae;
		} else {
			xfer_rae = true;
		}

		rc = __nvme_mi_admin_get_log_page(ctrl, nsid, log_id, xfer_rae,
						  offset + xfer_offset,
						  xfer_size,
						  data + xfer_offset);
		if (rc)
			break;
	}

	return rc;
}

int nvme_mi_admin_get_log_page(nvme_mi_ctrl_t ctrl, __u8 log_id,
			       bool rae, off_t offset, size_t size,
			       void *data)
{
	return nvme_mi_admin_get_log_page_nsid(ctrl, NVME_NSID_NONE, log_id,
					       rae, offset, size, data);
}

int nvme_mi_admin_security_send(nvme_mi_ctrl_t ctrl, __u8 secp,
				__u8 spsp1, __u8 spsp2, __u8 nssf,
				size_t size, void *data)
{

	struct nvme_mi_admin_resp_hdr resp_hdr;
	struct nvme_mi_admin_req_hdr req_hdr;
	struct nvme_mi_resp resp;
	struct nvme_mi_req req;
	int rc;

	if (size > 4096)
		return -EINVAL;

	nvme_mi_admin_init_req(&req, &req_hdr, ctrl->id,
			       nvme_admin_security_send);

	req_hdr.cdw10 = cpu_to_le32(secp << 24 |
				    spsp1 << 16 |
				    spsp2 << 8 |
				    nssf);

	req_hdr.cdw11 = cpu_to_le32(size & 0xffffffff);

	req_hdr.flags = 0x1;
	req_hdr.dlen = cpu_to_le32(size & 0xffffffff);

	nvme_mi_calc_req_mic(&req);

	nvme_mi_admin_init_resp(&resp, &resp_hdr);
	resp.data = data;
	resp.data_len = size;

	rc = nvme_mi_submit(ctrl->ep, &req, &resp);
	if (rc)
		return rc;

	if (resp_hdr.status)
		return resp_hdr.status;

	return 0;
}

int nvme_mi_admin_security_recv(nvme_mi_ctrl_t ctrl, __u8 secp,
				__u8 spsp1, __u8 spsp2, __u8 nssf,
				size_t *sizep, void *data)
{

	struct nvme_mi_admin_resp_hdr resp_hdr;
	struct nvme_mi_admin_req_hdr req_hdr;
	struct nvme_mi_resp resp;
	struct nvme_mi_req req;
	size_t size;
	int rc;

	size = *sizep;
	if (size > 4096)
		return -EINVAL;

	nvme_mi_admin_init_req(&req, &req_hdr, ctrl->id,
			       nvme_admin_security_recv);

	req_hdr.cdw10 = cpu_to_le32(secp << 24 |
				    spsp1 << 16 |
				    spsp2 << 8 |
				    nssf);

	req_hdr.cdw11 = cpu_to_le32(size & 0xffffffff);

	req_hdr.flags = 0x1;
	req_hdr.dlen = cpu_to_le32(size & 0xffffffff);

	nvme_mi_calc_req_mic(&req);

	nvme_mi_admin_init_resp(&resp, &resp_hdr);
	resp.data = data;
	resp.data_len = size;

	rc = nvme_mi_submit(ctrl->ep, &req, &resp);
	if (rc)
		return rc;

	if (resp_hdr.status)
		return resp_hdr.status;

	*sizep = resp.data_len;

	return 0;
}

static int nvme_mi_read_data(nvme_mi_ep_t ep, __u32 cdw0,
			     void *data, size_t *data_len)
{
	struct nvme_mi_mi_resp_hdr resp_hdr;
	struct nvme_mi_mi_req_hdr req_hdr;
	struct nvme_mi_resp resp;
	struct nvme_mi_req req;
	int rc;

	memset(&req_hdr, 0, sizeof(req_hdr));
	req_hdr.hdr.type = NVME_MI_MSGTYPE_NVME;
	req_hdr.hdr.nmp = (NVME_MI_ROR_REQ << 7) |
		(NVME_MI_MT_MI << 3); /* we always use command slot 0 */
	req_hdr.opcode = nvme_mi_mi_opcode_mi_data_read;
	req_hdr.cdw0 = cdw0;

	memset(&req, 0, sizeof(req));
	req.hdr = &req_hdr.hdr;
	req.hdr_len = sizeof(req_hdr);

	memset(&resp, 0, sizeof(resp));
	resp.hdr = &resp_hdr.hdr;
	resp.hdr_len = sizeof(resp_hdr);
	resp.data = data;
	resp.data_len = *data_len;

	rc = nvme_mi_submit(ep, &req, &resp);
	if (rc)
		return rc;

	*data_len = resp.data_len;

	/* check status, map to return value */
	return 0;
}

int nvme_mi_mi_read_mi_data_subsys(nvme_mi_ep_t ep,
				   struct nvme_mi_read_nvm_ss_info *s)
{
	size_t len;
	__u32 cdw0;
	int rc;

	cdw0 = (__u8)nvme_mi_dtyp_subsys_info << 24;
	len = sizeof(*s);

	rc = nvme_mi_read_data(ep, cdw0, s, &len);
	if (rc)
		return rc;

	if (len != sizeof(*s)) {
		nvme_msg(LOG_WARNING, "MI read data length mismatch: "
			 "got %zd bytes, expected %zd\n",
			 len, sizeof(*s));
		return -EPROTO;
	}

	return 0;
}

int nvme_mi_mi_read_mi_data_port(nvme_mi_ep_t ep, __u8 portid,
				 struct nvme_mi_read_port_info *p)
{
	size_t len;
	__u32 cdw0;
	int rc;

	cdw0 = ((__u8)nvme_mi_dtyp_port_info << 24) | (portid << 16);
	len = sizeof(*p);

	rc = nvme_mi_read_data(ep, cdw0, p, &len);
	if (rc)
		return rc;

	if (len != sizeof(*p)) {
		/* log? */
		return -EPROTO;
	}

	return 0;
}

int nvme_mi_mi_read_mi_data_ctrl_list(nvme_mi_ep_t ep, __u8 start_portid,
				       struct nvme_ctrl_list *list)
{
	size_t len;
	__u32 cdw0;
	int rc;

	cdw0 = ((__u8)nvme_mi_dtyp_ctrl_list << 24) | (start_portid << 16);
	len = sizeof(*list);

	rc = nvme_mi_read_data(ep, cdw0, list, &len);
	if (rc)
		return rc;

	return 0;
}

int nvme_mi_mi_read_mi_data_ctrl(nvme_mi_ep_t ep, __u16 ctrl_id,
				       struct nvme_mi_read_ctrl_info *ctrl)
{
	size_t len;
	__u32 cdw0;
	int rc;

	cdw0 = ((__u8)nvme_mi_dtyp_ctrl_info << 24) | cpu_to_le16(ctrl_id);
	len = sizeof(*ctrl);

	rc = nvme_mi_read_data(ep, cdw0, ctrl, &len);
	if (rc)
		return rc;

	if (len != sizeof(*ctrl))
		return -EPROTO;

	return 0;
}

int nvme_mi_mi_subsystem_health_status_poll(nvme_mi_ep_t ep, bool clear,
					    struct nvme_mi_nvm_ss_health_status *sshs)
{
	struct nvme_mi_mi_resp_hdr resp_hdr;
	struct nvme_mi_mi_req_hdr req_hdr;
	struct nvme_mi_resp resp;
	struct nvme_mi_req req;
	int rc;

	memset(&req_hdr, 0, sizeof(req_hdr));
	req_hdr.hdr.type = NVME_MI_MSGTYPE_NVME;;
	req_hdr.hdr.nmp = (NVME_MI_ROR_REQ << 7) |
		(NVME_MI_MT_MI << 3);
	req_hdr.opcode = nvme_mi_mi_opcode_subsys_health_status_poll;
	req_hdr.cdw1 = (clear ? 1 : 0) << 31;

	memset(&req, 0, sizeof(req));
	req.hdr = &req_hdr.hdr;
	req.hdr_len = sizeof(req_hdr);

	memset(&resp, 0, sizeof(resp));
	resp.hdr = &resp_hdr.hdr;
	resp.hdr_len = sizeof(resp_hdr);
	resp.data = sshs;
	resp.data_len = sizeof(*sshs);

	rc = nvme_mi_submit(ep, &req, &resp);
	if (rc)
		return rc;

	if (resp.data_len != sizeof(*sshs)) {
		nvme_msg(LOG_WARNING, "MI Subsystem Health Status length mismatch: "
			 "got %zd bytes, expected %zd\n",
			 resp.data_len, sizeof(*sshs));
		return -EIO;
	}

	/* check status, map to return value */
	return 0;
}

void nvme_mi_close(nvme_mi_ep_t ep)
{
	if (ep->transport->close)
		ep->transport->close(ep);
	free(ep);
}
