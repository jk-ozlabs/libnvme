// SPDX-License-Identifier: LGPL-2.1-or-later
/**
 * This file is part of libnvme.
 * Copyright (c) 2021 Code Construct Pty Ltd.
 *
 * Authors: Jeremy Kerr <jk@codeconstruct.com.au>
 */

/**
 * mi-mctp: open a MI connection over MCTP, and query controller info
 */

#include <assert.h>
#include <ctype.h>
#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <string.h>

#include <libnvme-mi.h>

#include <ccan/array_size/array_size.h>
#include <ccan/endian/endian.h>

static void show_port_pcie(struct nvme_mi_read_port_info *port)
{
	printf("    PCIe max payload: 0x%x\n", 0x80 << port->pcie.mps);
	printf("    PCIe link speeds: 0x%02x\n", port->pcie.sls);
	printf("    PCIe current speed: 0x%02x\n", port->pcie.cls);
	printf("    PCIe max link width: 0x%02x\n", port->pcie.mlw);
	printf("    PCIe neg link width: 0x%02x\n", port->pcie.nlw);
	printf("    PCIe port: 0x%02x\n", port->pcie.pn);
}

static void show_port_smbus(struct nvme_mi_read_port_info *port)
{
	printf("    SMBus address: 0x%02x\n", port->smb.vpd_addr);
	printf("    VPD access freq: 0x%02x\n", port->smb.mvpd_freq);
	printf("    MCTP address: 0x%02x\n", port->smb.mme_addr);
	printf("    MCTP access freq: 0x%02x\n", port->smb.mme_freq);
	printf("    NVMe basic management: %s\n",
	       (port->smb.nvmebm & 0x1) ? "enabled" : "disabled");
}

static struct {
	int typeid;
	const char *name;
	void (*fn)(struct nvme_mi_read_port_info *);
} port_types[] = {
	{ 0x00, "inactive", NULL },
	{ 0x01, "PCIe", show_port_pcie },
	{ 0x02, "SMBus", show_port_smbus },
};

static int show_port(nvme_mi_ep_t ep, int portid)
{
	void (*show_fn)(struct nvme_mi_read_port_info *);
	struct nvme_mi_read_port_info port;
	const char *typestr;
	int rc;

	rc = nvme_mi_mi_read_mi_data_port(ep, portid, &port);
	if (rc)
		return rc;

	if (port.portt < ARRAY_SIZE(port_types)) {
		show_fn = port_types[port.portt].fn;
		typestr = port_types[port.portt].name;
	} else {
		show_fn = NULL;
		typestr = "INVALID";
	}

	printf("  port %d\n", portid);
	printf("    type %s[%d]\n", typestr, port.portt);
	printf("    MCTP MTU: %d\n", port.mmctptus);
	printf("    MEB size: %d\n", port.meb);

	if (show_fn)
		show_fn(&port);

	return 0;
}

int do_info(nvme_mi_ep_t ep)
{
	struct nvme_mi_nvm_ss_health_status ss_health;
	struct nvme_mi_read_nvm_ss_info ss_info;
	int i, rc;

	rc = nvme_mi_mi_read_mi_data_subsys(ep, &ss_info);
	if (rc) {
		warn("can't perform Read MI Data operation");
		return -1;
	}

	printf("NVMe MI subsys info:\n");
	printf(" num ports: %d\n", ss_info.nump + 1);
	printf(" major ver: %d\n", ss_info.mjr);
	printf(" minor ver: %d\n", ss_info.mnr);

	printf("NVMe MI port info:\n");
	for (i = 0; i <= ss_info.nump; i++)
		show_port(ep, i);

	rc = nvme_mi_mi_subsystem_health_status_poll(ep, true, &ss_health);
	if (rc)
		err(EXIT_FAILURE, "can't perform Health Status Poll operation");

	printf("NVMe MI subsys health:\n");
	printf(" subsystem status:  0x%x\n", ss_health.nss);
	printf(" smart warnings:    0x%x\n", ss_health.sw);
	printf(" composite temp:    %d\n", ss_health.ctemp);
	printf(" drive life used:   %d%%\n", ss_health.pdlu);
	printf(" controller status: 0x%04x\n", le16_to_cpu(ss_health.pdlu));

	return 0;
}

static int show_ctrl(nvme_mi_ep_t ep, uint16_t ctrl_id)
{
	struct nvme_mi_read_ctrl_info ctrl;
	int rc;

	rc = nvme_mi_mi_read_mi_data_ctrl(ep, ctrl_id, &ctrl);
	if (rc)
		return rc;

	printf("  Controller id: %d\n", ctrl_id);
	printf("    port id: %d\n", ctrl.portid);
	if (ctrl.prii & 0x1) {
		uint16_t bdfn = le16_to_cpu(ctrl.pri);
		printf("    PCIe routing valid\n");
		printf("    PCIe bus: 0x%02x\n", bdfn >> 8);
		printf("    PCIe dev: 0x%02x\n", bdfn >> 3 & 0x1f);
		printf("    PCIe fn : 0x%02x\n", bdfn & 0x7);
	} else {
		printf("    PCIe routing invalid\n");
	}
	printf("    PCI vendor: %04x\n", le16_to_cpu(ctrl.vid));
	printf("    PCI device: %04x\n", le16_to_cpu(ctrl.did));
	printf("    PCI subsys vendor: %04x\n", le16_to_cpu(ctrl.ssvid));
	printf("    PCI subsys device: %04x\n", le16_to_cpu(ctrl.ssvid));

	return 0;
}

static int do_controllers(nvme_mi_ep_t ep)
{
	struct nvme_ctrl_list ctrl_list;
	int rc, i;

	rc = nvme_mi_mi_read_mi_data_ctrl_list(ep, 0, &ctrl_list);
	if (rc) {
		warnx("Can't perform Controller List operation");
		return rc;
	}

	printf("NVMe controller list:\n");
	for (i = 0; i < le16_to_cpu(ctrl_list.num); i++) {
		uint16_t id = le16_to_cpu(ctrl_list.identifier[i]);
		show_ctrl(ep, id);
	}
	return 0;
}

static const char *__copy_id_str(const void *field, size_t size,
				 char *buf, size_t buf_size)
{
	assert(size < buf_size);
	strncpy(buf, field, size);
	buf[size] = '\0';
	return buf;
}

#define copy_id_str(f,b) __copy_id_str(f, sizeof(f), b, sizeof(b))

int do_identify(nvme_mi_ep_t ep, int argc, char **argv)
{
	struct nvme_mi_ctrl *ctrl;
	struct nvme_id_ctrl id;
	uint16_t ctrl_id;
	char buf[41];
	int rc, tmp;

	if (argc != 2) {
		fprintf(stderr, "no controller ID specified\n");
		return -1;
	}

	tmp = atoi(argv[1]);
	if (tmp < 0 || tmp > 0xffff) {
		fprintf(stderr, "invalid controller ID\n");
		return -1;
	}

	ctrl_id = tmp & 0xffff;

	ctrl = nvme_mi_init_ctrl(ep, tmp);
	if (!ctrl) {
		warn("can't create controller");
		return -1;
	}

	/* we only use the fields before rab; just request partial ID data */
	rc = nvme_mi_admin_identify_ctrl_partial(ctrl, &id, 0,
					 offsetof(struct nvme_id_ctrl, rab));
	if (rc) {
		warn("can't perform Admin Identify command");
		return -1;
	}

	printf("NVMe Controller %d identify\n", ctrl_id);
	printf(" PCI vendor: %04x\n", le16_to_cpu(id.vid));
	printf(" PCI subsys vendor: %04x\n", le16_to_cpu(id.ssvid));
	printf(" Serial number: %s\n", copy_id_str(id.sn, buf));
	printf(" Model number: %s\n", copy_id_str(id.mn, buf));
	printf(" Firmware rev: %s\n", copy_id_str(id.fr, buf));

	return 0;
}

void fhexdump(FILE *fp, const unsigned char *buf, int len)
{
	const int row_len = 16;
	int i, j;

	for (i = 0; i < len; i += row_len) {
		char hbuf[row_len * strlen("00 ") + 1];
		char cbuf[row_len + strlen("|") + 1];

		for (j = 0; (j < row_len) && ((i+j) < len); j++) {
			unsigned char c = buf[i + j];

			sprintf(hbuf + j * 3, "%02x ", c);

			if (!isprint(c))
				c = '.';

			sprintf(cbuf + j, "%c", c);
		}

		strcat(cbuf, "|");

		fprintf(fp, "%08x  %*s |%s\n", i,
				0 - (int)sizeof(hbuf) + 1, hbuf, cbuf);
	}
}

void hexdump(const unsigned char *buf, int len)
{
	fhexdump(stdout, buf, len);
}

int do_get_log_page(nvme_mi_ep_t ep, int argc, char **argv)
{
	struct nvme_mi_ctrl *ctrl;
	uint8_t buf[512];
	uint16_t ctrl_id;
	uint8_t log_id;
	int rc, tmp;

	if (argc < 2) {
		fprintf(stderr, "no controller ID specified\n");
		return -1;
	}

	tmp = atoi(argv[1]);
	if (tmp < 0 || tmp > 0xffff) {
		fprintf(stderr, "invalid controller ID\n");
		return -1;
	}

	ctrl_id = tmp & 0xffff;

	if (argc > 2) {
		tmp = atoi(argv[2]);
		log_id = tmp & 0xff;
	} else {
		log_id = 0x1;
	}

	ctrl = nvme_mi_init_ctrl(ep, ctrl_id);
	if (!ctrl) {
		warn("can't create controller");
		return -1;
	}

	rc = nvme_mi_admin_get_log_page(ctrl, log_id, false, 0,
					sizeof(buf), buf);
	if (rc) {
		warn("can't perform Get Log page command");
		return -1;
	}

	printf("Get log page (log id = 0x%02x) data:\n", log_id);
	hexdump(buf, sizeof(buf));

	return 0;
}

enum action {
	ACTION_INFO,
	ACTION_CONTROLLERS,
	ACTION_IDENTIFY,
	ACTION_GET_LOG_PAGE,
};

int main(int argc, char **argv)
{
	enum action action;
	nvme_mi_ep_t ep;
	uint8_t eid;
	int rc, net;

	if (argc < 3) {
		fprintf(stderr,
			"usage: %s <net> <eid> [action] [action args]\n",
			argv[0]);
		fprintf(stderr, "where action is:\n"
			"  info\n"
			"  controllers\n"
			"  identify <controller-id>\n"
			"  get-log-page <controller-id> [<log-id>]\n"
			);
		return EXIT_FAILURE;
	}

	net = atoi(argv[1]);
	eid = atoi(argv[2]) & 0xff;
	argv += 2;
	argc -= 2;

	if (argc == 1) {
		action = ACTION_INFO;
	} else {
		char *action_str = argv[1];
		argc--;
		argv++;

		if (!strcmp(action_str, "info")) {
			action = ACTION_INFO;
		} else if (!strcmp(action_str, "controllers")) {
			action = ACTION_CONTROLLERS;
		} else if (!strcmp(action_str, "identify")) {
			action = ACTION_IDENTIFY;
		} else if (!strcmp(action_str, "get-log-page")) {
			action = ACTION_GET_LOG_PAGE;
		} else {
			fprintf(stderr, "invalid action '%s'\n", action_str);
			return EXIT_FAILURE;
		}
	}

	ep = nvme_mi_open_mctp(net, eid);
	if (!ep)
		err(EXIT_FAILURE, "can't open MCTP endpoint %d:%d", net, eid);

	switch (action) {
	case ACTION_INFO:
		rc = do_info(ep);
		break;
	case ACTION_CONTROLLERS:
		rc = do_controllers(ep);
		break;
	case ACTION_IDENTIFY:
		rc = do_identify(ep, argc, argv);
		break;
	case ACTION_GET_LOG_PAGE:
		rc = do_get_log_page(ep, argc, argv);
		break;
	}

	nvme_mi_close(ep);

	return rc ? EXIT_FAILURE : EXIT_SUCCESS;
}


