// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 * This file is part of libnvme.
 * Copyright (c) 2020 Western Digital Corporation or its affiliates.
 *
 * Authors: Keith Busch <keith.busch@wdc.com>
 * 	    Chaitanya Kulkarni <chaitanya.kulkarni@wdc.com>
 */

#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <dirent.h>
#include <libgen.h>
#include <unistd.h>

#include <sys/param.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <unistd.h>

#include "types.h"
#include "util.h"
#include "log.h"
#include "private.h"

static const char *nvme_ctrl_sysfs_dir = "/sys/class/nvme";
static const char *nvme_ns_sysfs_dir = "/sys/block";
static const char *nvme_subsys_sysfs_dir = "/sys/class/nvme-subsystem";

static int nvme_subsystem_scan_namespace(struct nvme_subsystem *s, char *name);
static int nvme_scan_subsystem(struct nvme_root *r, char *name,
			       nvme_scan_filter_t f);
static int nvme_subsystem_scan_ctrl(struct nvme_subsystem *s, char *name);
static int nvme_ctrl_scan_namespace(struct nvme_ctrl *c, char *name);
static int nvme_ctrl_scan_path(struct nvme_ctrl *c, char *name);

static int nvme_namespace_filter(const struct dirent *d)
{
	int i, n;

	if (d->d_name[0] == '.')
		return 0;

	if (strstr(d->d_name, "nvme"))
		if (sscanf(d->d_name, "nvme%dn%d", &i, &n) == 2)
			return 1;

	return 0;
}

static int nvme_paths_filter(const struct dirent *d)
{
	int i, c, n;

	if (d->d_name[0] == '.')
		return 0;

	if (strstr(d->d_name, "nvme"))
		if (sscanf(d->d_name, "nvme%dc%dn%d", &i, &c, &n) == 3)
			return 1;

	return 0;
}

static int nvme_ctrls_filter(const struct dirent *d)
{
	int i, c, n;

	if (d->d_name[0] == '.')
		return 0;

	if (strstr(d->d_name, "nvme")) {
		if (sscanf(d->d_name, "nvme%dc%dn%d", &i, &c, &n) == 3)
			return 0;
		if (sscanf(d->d_name, "nvme%dn%d", &i, &n) == 2)
			return 0;
		if (sscanf(d->d_name, "nvme%d", &i) == 1)
			return 1;
	}

	return 0;
}

static int nvme_subsys_filter(const struct dirent *d)
{
	int i;

	if (d->d_name[0] == '.')
		return 0;

	if (strstr(d->d_name, "nvme-subsys"))
		if (sscanf(d->d_name, "nvme-subsys%d", &i) == 1)
			return 1;

	return 0;
}

static int nvme_scan_subsystems(struct dirent ***subsys)
{
	return scandir(nvme_subsys_sysfs_dir, subsys, nvme_subsys_filter,
		       alphasort);
}

static int nvme_scan_subsystem_ctrls(nvme_subsystem_t s, struct dirent ***ctrls)
{
	return scandir(nvme_subsystem_get_sysfs_dir(s), ctrls,
		       nvme_ctrls_filter, alphasort);
}

static int nvme_scan_subsystem_namespaces(nvme_subsystem_t s, struct dirent ***namespaces)
{
	return scandir(nvme_subsystem_get_sysfs_dir(s), namespaces,
		       nvme_namespace_filter, alphasort);
}

static int nvme_scan_ctrl_namespace_paths(nvme_ctrl_t c, struct dirent ***namespaces)
{
	return scandir(nvme_ctrl_get_sysfs_dir(c), namespaces,
		       nvme_paths_filter, alphasort);
}

static int nvme_scan_ctrl_namespaces(nvme_ctrl_t c, struct dirent ***namespaces)
{
	return scandir(nvme_ctrl_get_sysfs_dir(c), namespaces,
		       nvme_namespace_filter, alphasort);
}

static inline void nvme_free_dirents(struct dirent **d, int i)
{
	while (i-- > 0)
		free(d[i]);
	free(d);
}

static int nvme_local_scan_topology(struct nvme_root *r, nvme_scan_filter_t f)
{
	struct dirent **subsys;
	int i, ret;

	ret = nvme_scan_subsystems(&subsys);
	if (ret < 0)
		return ret;

	for (i = 0; i < ret; i++)
		nvme_scan_subsystem(r, subsys[i]->d_name, f);

	nvme_free_dirents(subsys, i);
	return 0;
}

static int nvme_subsystem_scan_namespaces(struct nvme_subsystem *s)
{
	struct dirent **namespaces;
	int i, ret;

	ret = nvme_scan_subsystem_namespaces(s, &namespaces);
	if (ret < 0)
		return ret;

	for (i = 0; i < ret; i++)
		nvme_subsystem_scan_namespace(s, namespaces[i]->d_name);

	nvme_free_dirents(namespaces, i);
	return 0;
}

static int nvme_subsystem_scan_ctrls(struct nvme_subsystem *s)
{
	struct dirent **ctrls;
	int i, ret;

	ret = nvme_scan_subsystem_ctrls(s, &ctrls);
	if (ret < 0)
		return ret;

	for (i = 0; i < ret; i++)
		nvme_subsystem_scan_ctrl(s, ctrls[i]->d_name);

	nvme_free_dirents(ctrls, i);
	return 0;
}

static char *__nvme_get_attr(const char *path)
{
	char value[4096] = { 0 };
	int ret, fd;

	fd = open(path, O_RDONLY);
	if (fd < 0) {
		nvme_msg(LOG_DEBUG, "Failed to open %s: %s\n", path,
			 strerror(errno));
		return NULL;
	}

	ret = read(fd, value, sizeof(value) - 1);
	close(fd);
	if (ret < 0 || !strlen(value)) {
		return NULL;
	}

	if (value[strlen(value) - 1] == '\n')
		value[strlen(value) - 1] = '\0';
	while (strlen(value) > 0 && value[strlen(value) - 1] == ' ')
		value[strlen(value) - 1] = '\0';

	return strlen(value) ? strdup(value) : NULL;
}

static const char *nvme_attr_to_name(enum nvme_attr attr)
{
	switch (attr) {
	case NVME_ATTR_MODEL:
		return "model";
	case NVME_ATTR_SERIAL:
		return "serial";
	case NVME_ATTR_FIRMWARE_REV:
		return "firmware_rev";
	case NVME_ATTR_HOSTNQN:
		return "hostnqn";
	case NVME_ATTR_HOSTID:
		return "hostid";
	case NVME_ATTR_SUBSYSNQN:
		return "subsysnqn";
	case NVME_ATTR_ADDRESS:
		return "address";
	case NVME_ATTR_TRANSPORT:
		return "transport";
	case NVME_ATTR_ANA_STATE:
		return "ana_state";
	case NVME_ATTR_ANA_GRPID:
		return "ana_grpid";
	case NVME_ATTR_STATE:
		return "state";
	case NVME_ATTR_NUMA_NODE:
		return "numa_node";
	case NVME_ATTR_QUEUE_COUNT:
		return "queue_count";
	case NVME_ATTR_SQSIZE:
		return "sqsize";
	}
	return NULL;
}

static char *nvme_get_attr(const char *dir, enum nvme_attr attr)
{
	char *path, *value;
	const char *name;
	int ret;

	name = nvme_attr_to_name(attr);
	if (!name)
		return NULL;

	ret = asprintf(&path, "%s/%s", dir, name);
	if (ret < 0)
		return NULL;

	value = __nvme_get_attr(path);
	free(path);
	return value;
}

static int __nvme_set_attr(const char *path, const char *value)
{
	int ret, fd;

	fd = open(path, O_WRONLY);
	if (fd < 0) {
		nvme_msg(LOG_DEBUG, "Failed to open %s: %s\n", path,
			 strerror(errno));
		return -1;
	}
	ret = write(fd, value, strlen(value));
	close(fd);
	return ret;
}

static int nvme_set_attr(const char *dir, const char *attr, const char *value)
{
	char *path;
	int ret;

	ret = asprintf(&path, "%s/%s", dir, attr);
	if (ret < 0)
		return -1;

	ret = __nvme_set_attr(path, value);
	free(path);
	return ret;
}

static char *nvme_local_get_subsys_attr(nvme_subsystem_t s, enum nvme_attr attr)
{
	return nvme_get_attr(nvme_subsystem_get_sysfs_dir(s), attr);
}

static char *nvme_local_get_ctrl_attr(nvme_ctrl_t c, enum nvme_attr attr)
{
	return nvme_get_attr(nvme_ctrl_get_sysfs_dir(c), attr);
}

static char *nvme_local_get_ns_attr(nvme_ns_t n, enum nvme_attr attr)
{
	return nvme_get_attr(nvme_ns_get_sysfs_dir(n), attr);
}

static char *nvme_local_get_path_attr(nvme_path_t p, enum nvme_attr attr)
{
	return nvme_get_attr(nvme_path_get_sysfs_dir(p), attr);
}

static int nvme_init_subsystem(nvme_subsystem_t s, const char *name,
			       const char *path)
{
	s->model = nvme_get_attr(path, NVME_ATTR_MODEL);
	if (!s->model) {
		errno = ENODEV;
		return -1;
	}
	s->serial = nvme_get_attr(path, NVME_ATTR_SERIAL);
	s->firmware = nvme_get_attr(path, NVME_ATTR_FIRMWARE_REV);
	s->name = strdup(name);
	s->local.sysfs_dir = (char *)path;

	return 0;
}

static int nvme_scan_subsystem(struct nvme_root *r, char *name,
			       nvme_scan_filter_t f)
{
	struct nvme_subsystem *s;
	char *path, *subsysnqn;
	char *hostnqn, *hostid = NULL;
	nvme_host_t h = NULL;
	int ret;

	ret = asprintf(&path, "%s/%s", nvme_subsys_sysfs_dir, name);
	if (ret < 0)
		return ret;

	hostnqn = nvme_get_attr(path, NVME_ATTR_HOSTNQN);
	if (hostnqn) {
		hostid = nvme_get_attr(path, NVME_ATTR_HOSTID);
		h = nvme_lookup_host(r, hostnqn, hostid);
		free(hostnqn);
		if (hostid)
			free(hostid);
	}
	if (!h)
		h = nvme_default_host(r);
	if (!h) {
		errno = ENOMEM;
		return -1;
	}
	subsysnqn = nvme_get_attr(path, NVME_ATTR_SUBSYSNQN);
	if (!subsysnqn) {
		errno = ENODEV;
		goto free_path;
	}
	s = nvme_lookup_subsystem(h, name, subsysnqn);
	if (!s) {
		free(subsysnqn);
		errno = ENOMEM;
		goto free_path;
	}
	free(subsysnqn);
	if (!s->name) {
		ret = nvme_init_subsystem(s, name, path);
		if (ret < 0)
			return ret;
	}

	nvme_subsystem_scan_namespaces(s);
	nvme_subsystem_scan_ctrls(s);

	if (f && !f(s)) {
		__nvme_free_subsystem(s);
		return -1;
	}

	return 0;

free_path:
	free(path);
	return -1;
}

static void nvme_subsystem_set_path_ns(nvme_subsystem_t s, nvme_path_t p)
{
	char n_name[32] = { };
	int i, c, nsid, ret;
	nvme_ns_t n;

	ret = sscanf(nvme_path_get_name(p), "nvme%dc%dn%d", &i, &c, &nsid);
	if (ret != 3)
		return;

	sprintf(n_name, "nvme%dn%d", i, nsid);
	nvme_subsystem_for_each_ns(s, n) {
		if (!strcmp(n_name, nvme_ns_get_name(n))) {
			list_add(&n->paths, &p->nentry);
			p->n = n;
		}
	}
}

static int nvme_ctrl_scan_path(struct nvme_ctrl *c, char *name)
{
	struct nvme_path *p;
	char *path, *grpid;
	int ret;

	if (!c->s) {
		errno = ENXIO;
		return -1;
	}
	ret = asprintf(&path, "%s/%s", c->local.sysfs_dir, name);
	if (ret < 0) {
		errno = ENOMEM;
		return -1;
	}

	p = calloc(1, sizeof(*p));
	if (!p) {
		errno = ENOMEM;
		goto free_path;
	}

	p->c = c;
	p->name = strdup(name);
	p->sysfs_dir = path;
	p->ana_state = nvme_get_path_attr(p, NVME_ATTR_ANA_STATE);
	nvme_subsystem_set_path_ns(c->s, p);

	grpid = nvme_get_path_attr(p, NVME_ATTR_ANA_GRPID);
	if (grpid) {
		sscanf(grpid, "%d", &p->grpid);
		free(grpid);
	}

	list_node_init(&p->nentry);
	list_node_init(&p->entry);
	list_add(&c->paths, &p->entry);
	return 0;

free_path:
	free(path);
	return -1;
}

static int nvme_ctrl_scan_paths(struct nvme_ctrl *c)
{
	struct dirent **paths;
	int i, ret;

	ret = nvme_scan_ctrl_namespace_paths(c, &paths);
	if (ret < 0)
		return ret;

	for (i = 0; i < ret; i++)
		nvme_ctrl_scan_path(c, paths[i]->d_name);

	nvme_free_dirents(paths, i);
	return 0;
}

static int nvme_ctrl_scan_namespaces(struct nvme_ctrl *c)
{
	struct dirent **namespaces;
	int i, ret;

	ret = nvme_scan_ctrl_namespaces(c, &namespaces);
	for (i = 0; i < ret; i++)
		nvme_ctrl_scan_namespace(c, namespaces[i]->d_name);

	nvme_free_dirents(namespaces, i);
	return 0;
}

static char *nvme_ctrl_lookup_subsystem_name(nvme_ctrl_t c)
{
	struct dirent **subsys;
	char *subsys_name = NULL;
	DIR *d;
	int ret, i;
	char path[PATH_MAX];

	ret = nvme_scan_subsystems(&subsys);
	if (ret < 0)
		return NULL;
	for (i = 0; i < ret; i++) {
		sprintf(path, "%s/%s/%s", nvme_subsys_sysfs_dir,
			subsys[i]->d_name, c->name);
		d = opendir(path);
		if (!d)
			continue;
		subsys_name = strdup(subsys[i]->d_name);
		closedir(d);
		break;
	}
	nvme_free_dirents(subsys, i);
	return subsys_name;
}

static int __nvme_ctrl_init(nvme_ctrl_t c, const char *path, const char *name)
{
	DIR *d;

	d = opendir(path);
	if (!d) {
		errno = ENODEV;
		return -1;
	}
	closedir(d);

	c->local.fd = nvme_open(name);
	if (c->local.fd < 0)
		return c->local.fd;

	c->name = strdup(name);
	c->local.sysfs_dir = (char *)path;
	c->firmware = nvme_get_ctrl_attr(c, NVME_ATTR_FIRMWARE_REV);
	c->model = nvme_get_ctrl_attr(c, NVME_ATTR_MODEL);
	c->state = nvme_get_ctrl_attr(c, NVME_ATTR_STATE);
	c->numa_node = nvme_get_ctrl_attr(c, NVME_ATTR_NUMA_NODE);
	c->queue_count = nvme_get_ctrl_attr(c, NVME_ATTR_QUEUE_COUNT);
	c->serial = nvme_get_ctrl_attr(c, NVME_ATTR_SERIAL);
	c->sqsize = nvme_get_ctrl_attr(c, NVME_ATTR_SQSIZE);
	return 0;
}

static int nvme_local_init_ctrl(struct nvme_host *h, struct nvme_ctrl *c,
				int instance)
{
	nvme_subsystem_t s;
	char *subsys_name = NULL;
	char *path, *name;
	int ret;

	ret = asprintf(&name, "nvme%d", instance);
	if (ret < 0) {
		errno = ENOMEM;
		return -1;
	}
	ret = asprintf(&path, "%s/nvme%d", nvme_ctrl_sysfs_dir, instance);
	if (ret < 0) {
		errno = ENOMEM;
		goto out_free_name;
	}

	ret = __nvme_ctrl_init(c, path, name);
	if (ret < 0) {
		free(path);
		goto out_free_name;
	}

	c->address = nvme_get_attr(path, NVME_ATTR_ADDRESS);
	if (!c->address) {
		free(path);
		errno = ENXIO;
		ret = -1;
		goto out_free_name;
	}
	subsys_name = nvme_ctrl_lookup_subsystem_name(c);
	s = nvme_lookup_subsystem(h, subsys_name, c->subsysnqn);
	if (!s) {
		errno = ENXIO;
		ret = -1;
		goto out_free_subsys;
	}
	if (!s->name) {
		ret = asprintf(&path, "%s/%s", nvme_subsys_sysfs_dir,
			       subsys_name);
		if (ret > 0)
			ret = nvme_init_subsystem(s, subsys_name, path);
		if (ret < 0) {
			free(path);
			goto out_free_subsys;
		}
	}
	c->s = s;
	list_add(&s->ctrls, &c->entry);
out_free_subsys:
	free(subsys_name);
 out_free_name:
	free(name);
	return ret;
}

static nvme_ctrl_t nvme_ctrl_alloc(nvme_subsystem_t s, const char *path,
				   const char *name)
{
	nvme_ctrl_t c;
	char *addr, *address, *a, *e;
	char *transport, *traddr = NULL, *trsvcid = NULL;
	char *host_traddr = NULL, *host_iface = NULL;
	int ret;

	transport = nvme_get_attr(path, NVME_ATTR_TRANSPORT);
	if (!transport) {
		errno = ENXIO;
		return NULL;
	}
	/* Parse 'address' string into components */
	addr = nvme_get_attr(path, NVME_ATTR_ADDRESS);
	address = strdup(addr);
	if (!strcmp(transport, "pcie")) {
		/* The 'address' string is the transport address */
		traddr = address;
	} else {
		a = strtok_r(addr, ",", &e);
		while (a && strlen(a)) {
			if (!strncmp(a, "traddr=", 7))
				traddr = a + 7;
			else if (!strncmp(a, "trsvcid=", 8))
				trsvcid = a + 8;
			else if (!strncmp(a, "host_traddr=", 12))
				host_traddr = a + 12;
			else if (!strncmp(a, "host_iface=", 11))
				host_iface = a + 12;
			a = strtok_r(NULL, ",", &e);
		}
	}
	c = nvme_lookup_ctrl(s, transport, traddr,
			     host_traddr, host_iface, trsvcid);
	free(addr);
	if (!c) {
		errno = ENOMEM;
		return NULL;
	}
	c->address = address;
	ret = __nvme_ctrl_init(c, path, name);
	return (ret < 0) ? NULL : c;
}

static int nvme_local_ctrl_delete(struct nvme_ctrl *c)
{
	return nvme_set_attr(nvme_ctrl_get_sysfs_dir(c),
			    "delete_controller", "1");
}

static struct nvme_ctrl *nvme_local_scan_ctrl(struct nvme_root *r,
					      const char *name)
{
	nvme_host_t h;
	nvme_subsystem_t s;
	nvme_ctrl_t c;
	char *path;
	char *hostnqn, *hostid, *subsysnqn;
	int ret;

	ret = asprintf(&path, "%s/%s", nvme_ctrl_sysfs_dir, name);
	if (ret < 0) {
		errno = ENOMEM;
		return NULL;
	}

	hostnqn = nvme_get_attr(path, NVME_ATTR_HOSTNQN);
	hostid = nvme_get_attr(path, NVME_ATTR_HOSTID);
	h = nvme_lookup_host(r, hostnqn, hostid);
	if (hostnqn)
		free(hostnqn);
	if (hostid)
		free(hostid);
	if (!h) {
		h = nvme_default_host(r);
		if (!h) {
			free(path);
			errno = ENOMEM;
			return NULL;
		}
	}

	subsysnqn = nvme_get_attr(path, NVME_ATTR_SUBSYSNQN);
	if (!subsysnqn) {
		free(path);
		errno = ENXIO;
		return NULL;
	}
	s = nvme_lookup_subsystem(h, NULL, subsysnqn);
	if (!s) {
		free(path);
		errno = ENOMEM;
		return NULL;
	}
	c = nvme_ctrl_alloc(s, path, name);
	if (!c)
		free(path);

	return c;
}

static int nvme_subsystem_scan_ctrl(struct nvme_subsystem *s, char *name)
{
	nvme_ctrl_t c;
	char *path;

	if (asprintf(&path, "%s/%s", s->local.sysfs_dir, name) < 0) {
		errno = ENOMEM;
		return -1;
	}

	c = nvme_ctrl_alloc(s, path, name);
	if (!c) {
		free(path);
		return -1;
	}
	nvme_ctrl_scan_namespaces(c);
	nvme_ctrl_scan_paths(c);

	return 0;
}

static nvme_ns_t nvme_ns_open(const char *name)
{
	struct nvme_ns *n;

	n = calloc(1, sizeof(*n));
	if (!n) {
		errno = ENOMEM;
		return NULL;
	}

	n->name = strdup(name);
	n->local.fd = nvme_open(n->name);
	if (n->local.fd < 0)
		goto free_ns;

	if (nvme_get_nsid(n->local.fd, &n->nsid) < 0)
		goto close_fd;

	if (nvme_ns_init(n) != 0)
		goto close_fd;

	list_head_init(&n->paths);
	list_node_init(&n->entry);

	return n;

close_fd:
	close(n->local.fd);
free_ns:
	free(n->name);
	free(n);
	return NULL;
}

static struct nvme_ns *__nvme_scan_namespace(const char *sysfs_dir,
					     const char *name)
{
	struct nvme_ns *n;
	char *path;
	int ret;

	ret = asprintf(&path, "%s/%s", sysfs_dir, name);
	if (ret < 0) {
		errno = ENOMEM;
		return NULL;
	}

	n = nvme_ns_open(name);
	if (!n)
		goto free_path;

	n->local.sysfs_dir = path;
	return n;

free_path:
	free(path);
	return NULL;
}

static struct nvme_ns *nvme_local_scan_ns(struct nvme_root *r, const char *name)
{
	return __nvme_scan_namespace(nvme_ns_sysfs_dir, name);
}

static int nvme_ctrl_scan_namespace(struct nvme_ctrl *c, char *name)
{
	struct nvme_ns *n;

	if (!c->s) {
		errno = EINVAL;
		return -1;
	}
	n = __nvme_scan_namespace(c->local.sysfs_dir, name);
	if (!n)
		return -1;

	n->s = c->s;
	n->c = c;
	list_add(&c->namespaces, &n->entry);
	return 0;
}

static int nvme_subsystem_scan_namespace(struct nvme_subsystem *s, char *name)
{
	struct nvme_ns *n;

	n = __nvme_scan_namespace(s->local.sysfs_dir, name);
	if (!n)
		return -1;

	n->s = s;
	list_add(&s->namespaces, &n->entry);
	return 0;
}

static struct nvme_ns *nvme_local_subsys_lookup_ns(struct nvme_subsystem *s,
						   __u32 nsid)
{
	struct nvme_ns *n;
	char *name;
	int ret;

	ret = asprintf(&name, "%sn%u", s->name, nsid);
	if (ret < 0)
		return NULL;
	n = __nvme_scan_namespace(s->local.sysfs_dir, name);
	if (!n) {
		free(name);
		return NULL;
	}

	n->s = s;
	list_add(&s->namespaces, &n->entry);
	return n;
}

static void nvme_local_ctrl_rescan(struct nvme_ctrl *c)
{
	if (!c->s)
		return;
	nvme_subsystem_scan_namespaces(c->s);
	nvme_ctrl_scan_namespaces(c);
	nvme_ctrl_scan_paths(c);
}

struct nvme_ops local_ops = {
	.get_subsys_attr = nvme_local_get_subsys_attr,
	.get_ctrl_attr = nvme_local_get_ctrl_attr,
	.get_ns_attr = nvme_local_get_ns_attr,
	.get_path_attr = nvme_local_get_path_attr,
	.scan_topology = nvme_local_scan_topology,
	.ctrl_rescan = nvme_local_ctrl_rescan,
	.ctrl_delete = nvme_local_ctrl_delete,
	.ctrl_init = nvme_local_init_ctrl,

	.scan_ctrl = nvme_local_scan_ctrl,
	.scan_ns = nvme_local_scan_ns,
	.subsys_lookup_ns = nvme_local_subsys_lookup_ns,
};
