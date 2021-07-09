// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 * This file is part of libnvme.
 * Copyright (c) 2021 SUSE Software Solutions
 *
 * Authors: Hannes Reinecke <hare@suse.de>
 */

#ifndef _LIBNVME_PRIVATE_H
#define _LIBNVME_PRIVATE_H

#include <stdbool.h>
#include <stdint.h>

#include <ccan/list/list.h>

#include "fabrics.h"
#include "tree.h"

#ifdef CONFIG_LIBUUID
#include <uuid/uuid.h>
#endif

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

struct nvme_ns_local {
	int fd;
	char *sysfs_dir;
};

struct nvme_ns {
	struct list_node entry;
	struct list_head paths;

	struct nvme_subsystem *s;
	struct nvme_ctrl *c;

	struct nvme_ns_local local;

	__u32 nsid;
	char *name;

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

struct nvme_ctrl_local {
	int fd;
	char *sysfs_dir;
};

struct nvme_ctrl {
	struct list_node entry;
	struct list_head paths;
	struct list_head namespaces;
	struct nvme_subsystem *s;

	struct nvme_ctrl_local local;

	char *name;
	char *address;
	char *firmware;
	char *model;
	char *state;
	char *numa_node;
	char *queue_count;
	char *serial;
	char *sqsize;
	char *hostnqn;
	char *hostid;
	char *transport;
	char *subsysnqn;
	char *traddr;
	char *trsvcid;
	char *host_traddr;
	char *host_iface;
	bool discovered;
	bool persistent;
	struct nvme_fabrics_config cfg;
};

struct nvme_subsystem_local {
	char *sysfs_dir;
};

struct nvme_subsystem {
	struct list_node entry;
	struct list_head ctrls;
	struct list_head namespaces;
	struct nvme_host *h;

	struct nvme_subsystem_local local;

	char *name;
	char *subsysnqn;
	char *model;
	char *serial;
	char *firmware;
};

struct nvme_host {
	struct list_node entry;
	struct list_head subsystems;
	struct nvme_root *r;

	char *hostnqn;
	char *hostid;
};

struct nvme_ops {
	/* attribute access */
	char *(*get_subsys_attr)(struct nvme_subsystem *s, enum nvme_attr a);
	char *(*get_ctrl_attr)(struct nvme_ctrl *c, enum nvme_attr a);
	char *(*get_ns_attr)(struct nvme_ns *n, enum nvme_attr a);
	char *(*get_path_attr)(struct nvme_path *p, enum nvme_attr a);

	/* scan */
	int (*scan_topology)(struct nvme_root *r, nvme_scan_filter_t f);
	void (*ctrl_rescan)(struct nvme_ctrl *c);
	int (*ctrl_delete)(struct nvme_ctrl *c);

	/* direct scan. */
	/* TODO: actually needed in API? */
	struct nvme_ctrl *(*scan_ctrl)(struct nvme_root *r, const char *name);
	struct nvme_ns *(*scan_ns)(struct nvme_root *r, const char *name);
	struct nvme_ns *(*subsys_lookup_ns)(struct nvme_subsystem *s, __u32 id);

	/* init */
	int (*ctrl_init)(struct nvme_host *h, struct nvme_ctrl *c,
			 int instance);

};

struct nvme_root {
	char *config_file;
	struct list_head hosts;
	bool modified;
	struct nvme_ops *ops;
};

void json_read_config(nvme_root_t r, const char *config_file);

int json_update_config(nvme_root_t r, const char *config_file);

void __nvme_free_subsystem(struct nvme_subsystem *s);
void __nvme_free_host(struct nvme_host *h);
void __nvme_free_ctrl(nvme_ctrl_t c);

int nvme_scan_topology(struct nvme_root *r, nvme_scan_filter_t f);

int nvme_ns_init(struct nvme_ns *n);
int nvme_ctrl_delete(struct nvme_ctrl *c);

/* local implementations */
extern struct nvme_ops local_ops;

#endif /* _LIBNVME_PRIVATE_H */
