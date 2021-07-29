// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 * This file is part of libnvme.
 * Copyright (c) 2021 SUSE Software Solutions
 *
 * Authors: Hannes Reinecke <hare@suse.de>
 */

#ifndef _LIBNVME_PRIVATE_H
#define _LIBNVME_PRIVATE_H

#include <ccan/list/list.h>

#include "fabrics.h"
#include "mi.h"

#ifdef CONFIG_LIBUUID
#include <uuid/uuid.h>
#endif


extern const char *nvme_ctrl_sysfs_dir;
extern const char *nvme_subsys_sysfs_dir;
extern const char *nvme_ns_sysfs_dir;

struct nvme_path {
	struct list_node entry;
	struct list_node nentry;

	struct nvme_ctrl *c;
	struct nvme_ns *n;

	char *name;
	char *sysfs_dir;
	char *ana_state;
	int grpid;
};

struct nvme_ns {
	struct list_node entry;
	struct list_head paths;

	struct nvme_subsystem *s;
	struct nvme_ctrl *c;

	int fd;
	__u32 nsid;
	char *name;
	char *generic_name;
	char *sysfs_dir;

	int lba_shift;
	int lba_size;
	int meta_size;
	uint64_t lba_count;
	uint64_t lba_util;

	uint8_t eui64[8];
	uint8_t nguid[16];
#ifdef CONFIG_LIBUUID
	uuid_t  uuid;
#else
	uint8_t uuid[16];
#endif
	enum nvme_csi csi;
};

struct nvme_ctrl {
	struct list_node entry;
	struct list_head paths;
	struct list_head namespaces;
	struct nvme_subsystem *s;

	int fd;
	char *name;
	char *sysfs_dir;
	char *address;
	char *firmware;
	char *model;
	char *state;
	char *numa_node;
	char *queue_count;
	char *serial;
	char *sqsize;
	char *transport;
	char *subsysnqn;
	char *traddr;
	char *trsvcid;
	char *host_traddr;
	char *host_iface;
	char *dhchap_key;
	bool discovery_ctrl;
	bool discovered;
	bool persistent;
	struct nvme_fabrics_config cfg;
};

struct nvme_subsystem {
	struct list_node entry;
	struct list_head ctrls;
	struct list_head namespaces;
	struct nvme_host *h;

	char *name;
	char *sysfs_dir;
	char *subsysnqn;
	char *model;
	char *serial;
	char *firmware;
	char *subsystype;
};

struct nvme_host {
	struct list_node entry;
	struct list_head subsystems;
	struct nvme_root *r;

	char *hostnqn;
	char *hostid;
	char *dhchap_key;
};

struct nvme_root {
	char *config_file;
	struct list_head hosts;
	bool modified;
};

int nvme_set_attr(const char *dir, const char *attr, const char *value);

void json_read_config(nvme_root_t r, const char *config_file);

int json_update_config(nvme_root_t r, const char *config_file);

/* mi internal headers */

/* internal transport API */
struct nvme_mi_req {
	struct nvme_mi_msg_hdr *hdr;
	size_t hdr_len;
	void *data;
	size_t data_len;
	__u32 mic;
};

struct nvme_mi_resp {
	struct nvme_mi_msg_hdr *hdr;
	size_t hdr_len;
	void *data;
	size_t data_len;
	__u32 mic;
};

struct nvme_mi_transport {
	const char *name;
	bool mic_enabled;
	int (*submit)(struct nvme_mi_ep *ep,
		      struct nvme_mi_req *req,
		      struct nvme_mi_resp *resp);
	void (*close)(struct nvme_mi_ep *ep);
};

struct nvme_mi_ep {
	const struct nvme_mi_transport *transport;
	void *transport_data;
};

struct nvme_mi_ctrl {
	struct nvme_mi_ep	*ep;
	__u16			id;
};

struct nvme_mi_ep *nvme_mi_init_ep(void);

#endif /* _LIBNVME_PRIVATE_H */
