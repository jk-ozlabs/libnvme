// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 * This file is part of libnvme.
 * Copyright (c) 2020 Western Digital Corporation or its affiliates.
 *
 * Authors: Keith Busch <keith.busch@wdc.com>
 * 	    Chaitanya Kulkarni <chaitanya.kulkarni@wdc.com>
 */
#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <libgen.h>
#include <unistd.h>

#include <sys/types.h>
#include <arpa/inet.h>
#include <netdb.h>

#include <ccan/list/list.h>
#include "ioctl.h"
#include "tree.h"
#include "util.h"
#include "fabrics.h"
#include "log.h"
#include "private.h"

static struct nvme_host *default_host;


nvme_host_t nvme_default_host(nvme_root_t r)
{
	struct nvme_host *h;
	char *hostnqn, *hostid;

	hostnqn = nvmf_hostnqn_from_file();
	if (!hostnqn)
		hostnqn = nvmf_hostnqn_generate();
	hostid = nvmf_hostid_from_file();

	h = nvme_lookup_host(r, hostnqn, hostid);
	default_host = h;
	free(hostnqn);
	if (hostid)
		free(hostid);
	return h;
}

nvme_root_t nvme_scan_filter(nvme_scan_filter_t f)
{
	struct nvme_root *r = calloc(1, sizeof(*r));

	if (!r) {
		errno = ENOMEM;
		return NULL;
	}

	list_head_init(&r->hosts);
	r->ops = &local_ops;
	nvme_scan_topology(r, f);
	return r;
}

nvme_root_t nvme_scan(const char *config_file)
{
	nvme_root_t r = nvme_scan_filter(NULL);

	if (r && config_file) {
		json_read_config(r, config_file);
		r->config_file = strdup(config_file);
	}
	return r;
}

int nvme_update_config(nvme_root_t r)
{
	if (!r->modified || !r->config_file)
		return 0;
	return json_update_config(r, r->config_file);
}

nvme_host_t nvme_first_host(nvme_root_t r)
{
	return list_top(&r->hosts, struct nvme_host, entry);
}

nvme_host_t nvme_next_host(nvme_root_t r, nvme_host_t h)
{
	return h ? list_next(&r->hosts, h, entry) : NULL;
}

nvme_root_t nvme_host_get_root(nvme_host_t h)
{
	return h->r;
}

const char *nvme_host_get_hostnqn(nvme_host_t h)
{
	return h->hostnqn;
}

const char *nvme_host_get_hostid(nvme_host_t h)
{
	return h->hostid;
}

nvme_subsystem_t nvme_first_subsystem(nvme_host_t h)
{
	return list_top(&h->subsystems, struct nvme_subsystem, entry);
}

nvme_subsystem_t nvme_next_subsystem(nvme_host_t h, nvme_subsystem_t s)
{
	return s ? list_next(&h->subsystems, s, entry) : NULL;
}

void nvme_refresh_topology(nvme_root_t r)
{
	struct nvme_host *h, *_h;

	nvme_for_each_host_safe(r, h, _h)
		__nvme_free_host(h);
	nvme_scan_topology(r, NULL);
}

void nvme_reset_topology(nvme_root_t r)
{
	struct nvme_host *h, *_h;

	nvme_for_each_host_safe(r, h, _h)
		__nvme_free_host(h);
	nvme_scan_topology(r, NULL);
}

void nvme_free_tree(nvme_root_t r)
{
	struct nvme_host *h, *_h;

	nvme_for_each_host_safe(r, h, _h)
		__nvme_free_host(h);
	if (r->config_file)
		free(r->config_file);
	free(r);
}

const char *nvme_subsystem_get_nqn(nvme_subsystem_t s)
{
	return s->subsysnqn;
}

const char *nvme_subsystem_get_sysfs_dir(nvme_subsystem_t s)
{
	return s->local.sysfs_dir;
}

const char *nvme_subsystem_get_name(nvme_subsystem_t s)
{
	return s->name;
}

nvme_ctrl_t nvme_subsystem_first_ctrl(nvme_subsystem_t s)
{
	return list_top(&s->ctrls, struct nvme_ctrl, entry);
}

nvme_ctrl_t nvme_subsystem_next_ctrl(nvme_subsystem_t s, nvme_ctrl_t c)
{
	return c ? list_next(&s->ctrls, c, entry) : NULL;
}

nvme_host_t nvme_subsystem_get_host(nvme_subsystem_t s)
{
	return s->h;
}

nvme_ns_t nvme_subsystem_first_ns(nvme_subsystem_t s)
{
	return list_top(&s->namespaces, struct nvme_ns, entry);
}

nvme_ns_t nvme_subsystem_next_ns(nvme_subsystem_t s, nvme_ns_t n)
{
	return n ? list_next(&s->namespaces, n, entry) : NULL;
}

static void __nvme_free_ns(struct nvme_ns *n)
{
	list_del_init(&n->entry);
	close(n->local.fd);
	free(n->name);
	free(n->local.sysfs_dir);
	free(n);
}

/* Stub for SWIG */
void nvme_free_ns(struct nvme_ns *n)
{
}

void __nvme_free_subsystem(struct nvme_subsystem *s)
{
	struct nvme_ctrl *c, *_c;
	struct nvme_ns *n, *_n;

	list_del_init(&s->entry);
	nvme_subsystem_for_each_ctrl_safe(s, c, _c)
		__nvme_free_ctrl(c);

	nvme_subsystem_for_each_ns_safe(s, n, _n)
		__nvme_free_ns(n);

	free(s->name);
	free(s->local.sysfs_dir);
	free(s->subsysnqn);
	if (s->model)
		free(s->model);
	if (s->serial)
		free(s->serial);
	if (s->firmware)
		free(s->firmware);
	free(s);
}

/*
 * Stub for SWIG
 */
void nvme_free_subsystem(nvme_subsystem_t s)
{
}

struct nvme_subsystem *nvme_lookup_subsystem(struct nvme_host *h,
					     const char *name,
					     const char *subsysnqn)
{
	struct nvme_subsystem *s;

	nvme_for_each_subsystem(h, s) {
		if (strcmp(s->subsysnqn, subsysnqn))
			continue;
		if (name && s->name &&
		    strcmp(s->name, name))
			continue;
		return s;
	}
	s = calloc(1, sizeof(*s));
	if (!s)
		return NULL;

	s->h = h;
	s->subsysnqn = strdup(subsysnqn);
	list_head_init(&s->ctrls);
	list_head_init(&s->namespaces);
	list_node_init(&s->entry);
	list_add(&h->subsystems, &s->entry);
	h->r->modified = true;
	return s;
}

void __nvme_free_host(struct nvme_host *h)
{
	struct nvme_subsystem *s, *_s;

	list_del_init(&h->entry);
	nvme_for_each_subsystem_safe(h, s, _s)
		__nvme_free_subsystem(s);
	free(h->hostnqn);
	if (h->hostid)
		free(h->hostid);
	h->r->modified = true;
	free(h);
}

/* Stub for SWIG */
void nvme_free_host(struct nvme_host *h)
{
}

struct nvme_host *nvme_lookup_host(nvme_root_t r, const char *hostnqn,
				   const char *hostid)
{
	struct nvme_host *h;

	if (!hostnqn)
		return NULL;
	nvme_for_each_host(r, h) {
		if (strcmp(h->hostnqn, hostnqn))
			continue;
		if (hostid &&
		    strcmp(h->hostid, hostid))
			continue;
		return h;
	}
	h = calloc(1,sizeof(*h));
	if (!h)
		return NULL;
	h->hostnqn = strdup(hostnqn);
	if (hostid)
		h->hostid = strdup(hostid);
	list_head_init(&h->subsystems);
	list_node_init(&h->entry);
	h->r = r;
	list_add(&r->hosts, &h->entry);
	r->modified = true;

	return h;
}

nvme_ctrl_t nvme_path_get_subsystem(nvme_path_t p)
{
	return p->c;
}

nvme_ns_t nvme_path_get_ns(nvme_path_t p)
{
	return p->n;
}

const char *nvme_path_get_sysfs_dir(nvme_path_t p)
{
	return p->sysfs_dir;
}

const char *nvme_path_get_name(nvme_path_t p)
{
	return p->name;
}

const char *nvme_path_get_ana_state(nvme_path_t p)
{
	return p->ana_state;
}

void nvme_free_path(struct nvme_path *p)
{
	list_del_init(&p->entry);
	list_del_init(&p->nentry);
	free(p->name);
	free(p->sysfs_dir);
	free(p->ana_state);
	free(p);
}

int nvme_ctrl_get_fd(nvme_ctrl_t c)
{
	return c->local.fd;
}

nvme_subsystem_t nvme_ctrl_get_subsystem(nvme_ctrl_t c)
{
	return c->s;
}

const char *nvme_ctrl_get_name(nvme_ctrl_t c)
{
	return c->name;
}

const char *nvme_ctrl_get_sysfs_dir(nvme_ctrl_t c)
{
	return c->local.sysfs_dir;
}

const char *nvme_ctrl_get_subsysnqn(nvme_ctrl_t c)
{
	return c->s ? c->s->subsysnqn : c->subsysnqn;
}

const char *nvme_ctrl_get_address(nvme_ctrl_t c)
{
	return c->address;
}

const char *nvme_ctrl_get_firmware(nvme_ctrl_t c)
{
	return c->firmware;
}

const char *nvme_ctrl_get_model(nvme_ctrl_t c)
{
	return c->model;
}

const char *nvme_ctrl_get_state(nvme_ctrl_t c)
{
	char *state = c->state;

	c->state = nvme_get_ctrl_attr(c, NVME_ATTR_STATE);
	if (state)
		free(state);
	return c->state;
}

const char *nvme_ctrl_get_numa_node(nvme_ctrl_t c)
{
	return c->numa_node;
}

const char *nvme_ctrl_get_queue_count(nvme_ctrl_t c)
{
	return c->queue_count;
}

const char *nvme_ctrl_get_serial(nvme_ctrl_t c)
{
	return c->serial;
}

const char *nvme_ctrl_get_sqsize(nvme_ctrl_t c)
{
	return c->sqsize;
}

const char *nvme_ctrl_get_transport(nvme_ctrl_t c)
{
	return c->transport;
}

const char *nvme_ctrl_get_traddr(nvme_ctrl_t c)
{
	return c->traddr;
}

const char *nvme_ctrl_get_trsvcid(nvme_ctrl_t c)
{
	return c->trsvcid;
}

const char *nvme_ctrl_get_host_traddr(nvme_ctrl_t c)
{
	return c->host_traddr;
}

const char *nvme_ctrl_get_host_iface(nvme_ctrl_t c)
{
	return c->host_iface;
}

const char *nvme_ctrl_get_hostnqn(nvme_ctrl_t c)
{
	if (!c->s)
		return default_host->hostnqn;
	return c->s->h->hostnqn;
}

const char *nvme_ctrl_get_hostid(nvme_ctrl_t c)
{
	if (!c->s)
		return default_host->hostid;
	return c->s->h->hostid;
}

struct nvme_fabrics_config *nvme_ctrl_get_config(nvme_ctrl_t c)
{
	return &c->cfg;
}

void nvme_ctrl_disable_sqflow(nvme_ctrl_t c, bool disable_sqflow)
{
	c->cfg.disable_sqflow = disable_sqflow;
	if (c->s && c->s->h && c->s->h->r)
		c->s->h->r->modified = true;
}

void nvme_ctrl_set_discovered(nvme_ctrl_t c, bool discovered)
{
	c->discovered = discovered;
}

bool nvme_ctrl_is_discovered(nvme_ctrl_t c)
{
	return c->discovered;
}

void nvme_ctrl_set_persistent(nvme_ctrl_t c, bool persistent)
{
	c->persistent = persistent;
}

bool nvme_ctrl_is_persistent(nvme_ctrl_t c)
{
	return c->persistent;
}

int nvme_ctrl_identify(nvme_ctrl_t c, struct nvme_id_ctrl *id)
{
	return nvme_identify_ctrl(nvme_ctrl_get_fd(c), id);
}

nvme_ns_t nvme_ctrl_first_ns(nvme_ctrl_t c)
{
	return list_top(&c->namespaces, struct nvme_ns, entry);
}

nvme_ns_t nvme_ctrl_next_ns(nvme_ctrl_t c, nvme_ns_t n)
{
	return n ? list_next(&c->namespaces, n, entry) : NULL;
}

nvme_path_t nvme_ctrl_first_path(nvme_ctrl_t c)
{
	return list_top(&c->paths, struct nvme_path, entry);
}

nvme_path_t nvme_ctrl_next_path(nvme_ctrl_t c, nvme_path_t p)
{
	return p ? list_next(&c->paths, p, entry) : NULL;
}

#define FREE_CTRL_ATTR(a) \
	do { if (a) { free(a); (a) = NULL; } } while (0)
int nvme_disconnect_ctrl(nvme_ctrl_t c)
{
	int ret;

	ret = nvme_ctrl_delete(c);
	if (ret < 0) {
		nvme_msg(LOG_ERR, "%s: failed to disconnect, error %d\n",
			 c->name, errno);
		return ret;
	}
	nvme_msg(LOG_INFO, "%s: disconnected\n", c->name);
	if (c->local.fd >= 0) {
		close(c->local.fd);
		c->local.fd = -1;
	}
	FREE_CTRL_ATTR(c->local.sysfs_dir);
	FREE_CTRL_ATTR(c->name);
	FREE_CTRL_ATTR(c->firmware);
	FREE_CTRL_ATTR(c->model);
	FREE_CTRL_ATTR(c->state);
	FREE_CTRL_ATTR(c->numa_node);
	FREE_CTRL_ATTR(c->queue_count);
	FREE_CTRL_ATTR(c->serial);
	FREE_CTRL_ATTR(c->sqsize);
	FREE_CTRL_ATTR(c->address);

	return 0;
}

void nvme_unlink_ctrl(nvme_ctrl_t c)
{
	list_del_init(&c->entry);
	c->s = NULL;
}

void __nvme_free_ctrl(nvme_ctrl_t c)
{
	struct nvme_path *p, *_p;
	struct nvme_ns *n, *_n;

	nvme_unlink_ctrl(c);

	nvme_ctrl_for_each_path_safe(c, p, _p)
		nvme_free_path(p);

	nvme_ctrl_for_each_ns_safe(c, n, _n)
		__nvme_free_ns(n);

	if (c->local.fd >= 0)
		close(c->local.fd);
	if (c->local.sysfs_dir)
		free(c->local.sysfs_dir);
	if (c->name)
		free(c->name);
	if (c->address)
		free(c->address);
	if (c->traddr)
		free(c->traddr);
	if (c->trsvcid)
		free(c->trsvcid);
	if (c->host_traddr)
		free(c->host_traddr);
	if (c->host_iface)
		free(c->host_iface);
	free(c->firmware);
	free(c->model);
	free(c->state);
	free(c->numa_node);
	free(c->queue_count);
	free(c->serial);
	free(c->sqsize);
	free(c->transport);
	free(c);
}

/* Stub for SWIG */
void nvme_free_ctrl(nvme_ctrl_t c)
{
}

#define ____stringify(x...) #x
#define __stringify(x...) ____stringify(x)

static void discovery_trsvcid(nvme_ctrl_t c)
{
	if (!strcmp(c->transport, "tcp")) {
		/* Default port for NVMe/TCP discovery controllers */
		c->trsvcid = strdup(__stringify(NVME_DISC_IP_PORT));
	} else if (!strcmp(c->transport, "rdma")) {
		/* Default port for NVMe/RDMA controllers */
		c->trsvcid = strdup(__stringify(NVME_RDMA_IP_PORT));
	}
}

static bool traddr_is_hostname(const char *transport, const char *traddr)
{
	char addrstr[NVMF_TRADDR_SIZE];

	if (!traddr || !transport)
		return false;
	if (strcmp(transport, "tcp") &&
	    strcmp(transport, "rdma"))
		return false;
	if (inet_pton(AF_INET, traddr, addrstr) > 0 ||
	    inet_pton(AF_INET6, traddr, addrstr) > 0)
		return false;
	return true;
}

void hostname2traddr(nvme_ctrl_t c, const char *host_traddr)
{
	struct addrinfo *host_info, hints = {.ai_family = AF_UNSPEC};
	char addrstr[NVMF_TRADDR_SIZE];
	const char *p;
	int ret;

	ret = getaddrinfo(host_traddr, NULL, &hints, &host_info);
	if (ret) {
		nvme_msg(LOG_DEBUG, "failed to resolve host %s info\n",
			 host_traddr);
		c->host_traddr = strdup(host_traddr);
		return;
	}

	switch (host_info->ai_family) {
	case AF_INET:
		p = inet_ntop(host_info->ai_family,
			&(((struct sockaddr_in *)host_info->ai_addr)->sin_addr),
			addrstr, NVMF_TRADDR_SIZE);
		break;
	case AF_INET6:
		p = inet_ntop(host_info->ai_family,
			&(((struct sockaddr_in6 *)host_info->ai_addr)->sin6_addr),
			addrstr, NVMF_TRADDR_SIZE);
		break;
	default:
		nvme_msg(LOG_DEBUG, "unrecognized address family (%d) %s\n",
			 host_info->ai_family, c->traddr);
		c->host_traddr = strdup(host_traddr);
		goto free_addrinfo;
	}
	if (!p) {
		nvme_msg(LOG_DEBUG, "failed to get traddr for %s\n",
			 c->traddr);
		c->host_traddr = strdup(host_traddr);
	} else
		c->host_traddr = strdup(addrstr);

free_addrinfo:
	freeaddrinfo(host_info);
}

struct nvme_ctrl *nvme_create_ctrl(const char *subsysnqn, const char *transport,
				   const char *traddr, const char *host_traddr,
				   const char *host_iface, const char *trsvcid)
{
	struct nvme_ctrl *c;
	bool discovery = false;

	if (!transport) {
		nvme_msg(LOG_ERR, "No transport specified\n");
		return NULL;
	}
	if (strncmp(transport, "loop", 4) && !traddr) {
               nvme_msg(LOG_ERR, "No transport address for '%s'\n", transport);
	       return NULL;
	}
	if (!subsysnqn) {
		nvme_msg(LOG_ERR, "No subsystem NQN specified\n");
		return NULL;
	} else if (!strcmp(subsysnqn, NVME_DISC_SUBSYS_NAME))
		discovery = true;
	c = calloc(1, sizeof(*c));
	c->local.fd = -1;
	c->cfg.tos = -1;
	list_head_init(&c->namespaces);
	list_head_init(&c->paths);
	list_node_init(&c->entry);
	c->transport = strdup(transport);
	c->subsysnqn = strdup(subsysnqn);
	if (traddr)
		c->traddr = strdup(traddr);
	if (host_traddr) {
		if (traddr_is_hostname(transport, host_traddr))
			hostname2traddr(c, host_traddr);
		else
			c->host_traddr = strdup(host_traddr);
	}
	if (host_iface)
		c->host_iface = strdup(host_iface);
	if (trsvcid)
		c->trsvcid = strdup(trsvcid);
	else if (discovery)
		discovery_trsvcid(c);
	else if (!strncmp(transport, "rdma", 4) ||
		 !strncmp(transport, "tcp", 3)) {
		nvme_msg(LOG_ERR, "No trsvcid specified for '%s'\n",
			 transport);
		__nvme_free_ctrl(c);
		c = NULL;
	}

	return c;
}

struct nvme_ctrl *nvme_lookup_ctrl(struct nvme_subsystem *s, const char *transport,
				   const char *traddr, const char *host_traddr,
				   const char *host_iface, const char *trsvcid)
{
	struct nvme_ctrl *c;

	if (!s || !transport)
		return NULL;
	nvme_subsystem_for_each_ctrl(s, c) {
		if (strcmp(c->transport, transport))
			continue;
		if (traddr && c->traddr &&
		    strcmp(c->traddr, traddr))
			continue;
		if (host_traddr && c->host_traddr &&
		    strcmp(c->host_traddr, host_traddr))
			continue;
		if (host_iface && c->host_iface &&
		    strcmp(c->host_iface, host_iface))
			continue;
		if (trsvcid && c->trsvcid &&
		    strcmp(c->trsvcid, trsvcid))
			continue;
		return c;
	}
	c = nvme_create_ctrl(s->subsysnqn, transport, traddr,
			     host_traddr, host_iface, trsvcid);
	if (c) {
		c->s = s;
		list_add(&s->ctrls, &c->entry);
		s->h->r->modified = true;
	}
	return c;
}

char *nvme_get_subsystem_attr(nvme_subsystem_t s, enum nvme_attr attr)
{
	return s->h->r->ops->get_subsys_attr(s, attr);
}

char *nvme_get_ctrl_attr(nvme_ctrl_t c, enum nvme_attr attr)
{
	if (!c->s)
		return NULL;
	return c->s->h->r->ops->get_ctrl_attr(c, attr);
}

char *nvme_get_ns_attr(nvme_ns_t n, enum nvme_attr attr)
{
	struct nvme_subsystem *s;
	s = n->s ?: n->c->s;
	return s->h->r->ops->get_ns_attr(n, attr);
}

char *nvme_get_path_attr(nvme_path_t p, enum nvme_attr attr)
{
	return p->c->s->h->r->ops->get_path_attr(p, attr);
}

int nvme_scan_topology(nvme_root_t r, nvme_scan_filter_t f)
{
	return r->ops->scan_topology(r, f);
}

void nvme_rescan_ctrl(nvme_ctrl_t c)
{
	if (!c->s)
		return;
	return c->s->h->r->ops->ctrl_rescan(c);
}

int nvme_init_ctrl(nvme_host_t h, nvme_ctrl_t c, int instance)
{
	return h->r->ops->ctrl_init(h, c, instance);
}

int nvme_ctrl_delete(nvme_ctrl_t c)
{
	if (!c->s)
		return EINVAL;
	return c->s->h->r->ops->ctrl_delete(c);
}

nvme_ctrl_t nvme_scan_ctrl(nvme_root_t r, const char *name)
{
	return r->ops->scan_ctrl(r, name);
}

nvme_ns_t nvme_scan_ns(nvme_root_t r, const char *name)
{
	return r->ops->scan_ns(r, name);
}

nvme_ns_t nvme_subsystem_lookup_namespace(nvme_subsystem_t s, __u32 nsid)
{
	return s->h->r->ops->subsys_lookup_ns(s, nsid);
}


static int nvme_bytes_to_lba(nvme_ns_t n, off_t offset, size_t count,
			    __u64 *lba, __u16 *nlb)
{
	int bs;

	bs = nvme_ns_get_lba_size(n);
	if (!count || offset & bs || count & bs) {
		errno = EINVAL;
		return -1;
	}

	*lba = offset >> n->lba_shift;
	*nlb = (count >> n->lba_shift) - 1;
	return 0;
}

int nvme_ns_get_fd(nvme_ns_t n)
{
	return n->local.fd;
}

nvme_subsystem_t nvme_ns_get_subsystem(nvme_ns_t n)
{
	return n->s;
}

nvme_ctrl_t nvme_ns_get_ctrl(nvme_ns_t n)
{
	return n->c;
}

int nvme_ns_get_nsid(nvme_ns_t n)
{
	return n->nsid;
}

const char *nvme_ns_get_sysfs_dir(nvme_ns_t n)
{
	return n->local.sysfs_dir;
}

const char *nvme_ns_get_name(nvme_ns_t n)
{
	return n->name;
}

const char *nvme_ns_get_model(nvme_ns_t n)
{
	return n->c ? n->c->model : n->s->model;
}

const char *nvme_ns_get_serial(nvme_ns_t n)
{
	return n->c ? n->c->serial : n->s->serial;
}

const char *nvme_ns_get_firmware(nvme_ns_t n)
{
	return n->c ? n->c->firmware : n->s->firmware;
}

int nvme_ns_get_lba_size(nvme_ns_t n)
{
	return n->lba_size;
}

int nvme_ns_get_meta_size(nvme_ns_t n)
{
	return n->meta_size;
}

uint64_t nvme_ns_get_lba_count(nvme_ns_t n)
{
	return n->lba_count;
}

uint64_t nvme_ns_get_lba_util(nvme_ns_t n)
{
	return n->lba_util;
}

enum nvme_csi nvme_ns_get_csi(nvme_ns_t n)
{
	return n->csi;
}

const uint8_t *nvme_ns_get_eui64(nvme_ns_t n)
{
	return n->eui64;
}

const uint8_t *nvme_ns_get_nguid(nvme_ns_t n)
{
	return n->nguid;
}

#ifdef CONFIG_LIBUUID
void nvme_ns_get_uuid(nvme_ns_t n, uuid_t out)
{
	uuid_copy(out, n->uuid);
}
#else
void nvme_ns_get_uuid(nvme_ns_t n, uint8_t *out)
{
	memcpy(out, n, 16);
}
#endif

int nvme_ns_identify(nvme_ns_t n, struct nvme_id_ns *ns)
{
	return nvme_identify_ns(nvme_ns_get_fd(n), nvme_ns_get_nsid(n), ns);
}

int nvme_ns_identify_descs(nvme_ns_t n, struct nvme_ns_id_desc *descs)
{
	return nvme_identify_ns_descs(nvme_ns_get_fd(n), nvme_ns_get_nsid(n), descs);
}

int nvme_ns_verify(nvme_ns_t n, off_t offset, size_t count)
{
	__u64 slba;
	__u16 nlb;

	if (nvme_bytes_to_lba(n, offset, count, &slba, &nlb))
		return -1;

	return nvme_verify(nvme_ns_get_fd(n), nvme_ns_get_nsid(n), slba, nlb,
			   0, 0, 0, 0);
}

int nvme_ns_write_uncorrectable(nvme_ns_t n, off_t offset, size_t count)
{
	__u64 slba;
	__u16 nlb;

	if (nvme_bytes_to_lba(n, offset, count, &slba, &nlb))
		return -1;

	return nvme_write_uncorrectable(nvme_ns_get_fd(n), nvme_ns_get_nsid(n),
					slba, nlb);
}

int nvme_ns_write_zeros(nvme_ns_t n, off_t offset, size_t count)
{
	__u64 slba;
	__u16 nlb;

	if (nvme_bytes_to_lba(n, offset, count, &slba, &nlb))
		return -1;

	return nvme_write_zeros(nvme_ns_get_fd(n), nvme_ns_get_nsid(n), slba,
				nlb, 0, 0, 0, 0);
}

int nvme_ns_write(nvme_ns_t n, void *buf, off_t offset, size_t count)
{
	__u64 slba;
	__u16 nlb;

	if (nvme_bytes_to_lba(n, offset, count, &slba, &nlb))
		return -1;

	return nvme_write(nvme_ns_get_fd(n), nvme_ns_get_nsid(n), slba, nlb, 0,
			  0, 0, 0, 0, 0, count, buf, 0, NULL);
}

int nvme_ns_read(nvme_ns_t n, void *buf, off_t offset, size_t count)
{
	__u64 slba;
	__u16 nlb;

	if (nvme_bytes_to_lba(n, offset, count, &slba, &nlb))
		return -1;

	return nvme_read(nvme_ns_get_fd(n), nvme_ns_get_nsid(n), slba, nlb, 0,
			 0, 0, 0, 0, count, buf, 0, NULL);
}

int nvme_ns_compare(nvme_ns_t n, void *buf, off_t offset, size_t count)
{
	__u64 slba;
	__u16 nlb;

	if (nvme_bytes_to_lba(n, offset, count, &slba, &nlb))
		return -1;

	return nvme_compare(nvme_ns_get_fd(n), nvme_ns_get_nsid(n), slba, nlb,
			    0, 0, 0, 0, count, buf, 0, NULL);
}

int nvme_ns_flush(nvme_ns_t n)
{
	return nvme_flush(nvme_ns_get_fd(n), nvme_ns_get_nsid(n));
}

static void nvme_ns_parse_descriptors(struct nvme_ns *n,
				      struct nvme_ns_id_desc *descs)
{
	void *d = descs;
	int i, len;

	for (i = 0; i < NVME_IDENTIFY_DATA_SIZE; i += len) {
		struct nvme_ns_id_desc *desc = d + i;

		if (!desc->nidl)
			break;
		len = desc->nidl + sizeof(*desc);

		switch (desc->nidt) {
		case NVME_NIDT_EUI64:
			memcpy(n->eui64, desc->nid, sizeof(n->eui64));
			break;
		case NVME_NIDT_NGUID:
			memcpy(n->nguid, desc->nid, sizeof(n->nguid));
			break;
		case NVME_NIDT_UUID:
			memcpy(n->uuid, desc->nid, sizeof(n->uuid));
			break;
		case NVME_NIDT_CSI:
			memcpy(&n->csi, desc->nid, sizeof(n->csi));
			break;
		}
	}
}

int nvme_ns_init(struct nvme_ns *n)
{
	struct nvme_id_ns ns = { };
	uint8_t buffer[NVME_IDENTIFY_DATA_SIZE] = { };
	struct nvme_ns_id_desc *descs = (void *)buffer;
	int flbas;
	int ret;

	ret = nvme_ns_identify(n, &ns);
	if (ret)
		return ret;

	flbas = ns.flbas & NVME_NS_FLBAS_LBA_MASK;
	n->lba_shift = ns.lbaf[flbas].ds;
	n->lba_size = 1 << n->lba_shift;
	n->lba_count = le64_to_cpu(ns.nsze);
	n->lba_util = le64_to_cpu(ns.nuse);
	n->meta_size = le16_to_cpu(ns.lbaf[flbas].ms);

	if (!nvme_ns_identify_descs(n, descs))
		nvme_ns_parse_descriptors(n, descs);

	return 0;
}
