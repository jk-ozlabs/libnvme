NAME=libnvme
SPECFILE=$(NAME).spec
VERSION=$(shell awk '/Version:/ { print $$2 }' $(SPECFILE))

ifneq ($(MAKECMDGOALS),clean)
include ../config-host.mak
endif

prefix ?= /usr
includedir ?= $(prefix)/include
libdir ?= $(prefix)/lib

CCANDIR=../ccan/

CFLAGS ?= -g -fomit-frame-pointer -O2 -I/usr/include -Invme/ -I$(CCANDIR) -include ../config-host.h -D_GNU_SOURCE
override CFLAGS += -Wall -fPIC
SO_CFLAGS=-shared $(CFLAGS)
L_CFLAGS=$(CFLAGS)
LINK_FLAGS= -L /usr/lib64
LINK_FLAGS+=$(LDFLAGS)
ENABLE_SHARED ?= 1
SED ?= sed
INSTALL ?= install

libnvme_soname=$(NAME).so.1
libnvme_spec_soname=$(NAME)-spec.so.1
minor=0
micro=1
libnvme_name=$(libnvme_soname).$(minor).$(micro)
libnvme_spec_name=$(libnvme_spec_soname).$(minor).$(micro)
all_targets += $(NAME)-spec.a $(NAME).a

ifeq ($(ENABLE_SHARED),1)
all_targets += $(libnvme_spec_name) $(libnvme_name)
endif

include ../Makefile.quiet

all: $(all_targets)

$(CCANDIR)config.h: $(CCANDIR)tools/configurator/configurator
	$< > $@

libccan_headers := $(wildcard $(CCANDIR)ccan/*/*.h)
libccan_srcs := $(wildcard $(CCANDIR)ccan/*/*.c)
libccan_objs := $(patsubst %.c,%.ol,$(libccan_srcs))
libccan_sobjs := $(patsubst %.c,%.os,$(libccan_srcs))

$(libccan_objs) $(libccan_sobjs): $(libccan_headers) $(CCANDIR)config.h

libnvme_priv := nvme/private.h
libnvme_api := libnvme.h nvme/types.h nvme/cmd.h nvme/ioctl.h nvme/filters.h nvme/tree.h nvme/spec-helpers.h nvme/util.h nvme/fabrics.h
libnvme_srcs := nvme/ioctl.c nvme/filters.c nvme/fabrics.c nvme/spec-helpers.c nvme/util.c nvme/tree.c nvme/log.c nvme/cleanup.c

ifeq ($(CONFIG_JSONC),y)
override libnvme_srcs += nvme/json.c
endif

libnvme_objs := $(patsubst %.c,%.ol,$(libnvme_srcs))
libnvme_sobjs := $(patsubst %.c,%.os,$(libnvme_srcs))

$(libnvme_objs) $(libnvme_sobjs): $(libnvme_api) $(libnvme_private) $(libccan_objs)

libnvme_spec_api := nvme/types.h nvme/cmd.h nvme/spec-helpers.h
libnvme_spec_srcs := nvme/spec-helpers.c
libnvme_spec_objs := $(patsubst %.c,%.ol,$(libnvme_spec_srcs))
libnvme_spec_sobjs := $(patsubst %.c,%.os,$(libnvme_spec_srcs))

$(libnvme_spec_objs) $(libnvme_spec_sobjs): $(libnvme_spec_api) $(libccan_objs)

%.os: %.c
	$(QUIET_CC)$(CC) $(SO_CFLAGS) -c -o $@ $<

%.ol: %.c
	$(QUIET_CC)$(CC) $(L_CFLAGS) -c -o $@ $<

AR ?= ar
RANLIB ?= ranlib

libnvme.a: $(libnvme_objs) $(libccan_objs)
	@rm -f libnvme.a
	$(QUIET_AR)$(AR) r libnvme.a $^
	$(QUIET_RANLIB)$(RANLIB) libnvme.a

$(libnvme_name): $(libnvme_sobjs) $(libccan_sobjs) libnvme.map
	$(QUIET_CC)$(CC) $(SO_CFLAGS) -Wl,--version-script=libnvme.map -Wl,-soname=$(libnvme_soname) -o $@ $(libnvme_sobjs) $(libccan_sobjs) $(LINK_FLAGS)

libnvme-spec.a: $(libnvme_spec_objs) $(libccan_objs)
	@rm -f libnvme-spec.a
	$(QUIET_AR)$(AR) r libnvme-spec.a $^
	$(QUIET_RANLIB)$(RANLIB) libnvme-spec.a

$(libnvme_spec_name): $(libnvme_spec_sobjs) $(libccan_sobjs)
	$(QUIET_CC)$(CC) $(SO_CFLAGS) -Wl,-soname=$(libnvme_spec_soname) -o $@ $(libnvme_spec_sobjs) $(libccan_sobjs) $(LINK_FLAGS)

install: $(all_targets)
	$(INSTALL) -D -m 644 libnvme.a $(libdir)/libnvme.a
	$(INSTALL) -D -m 644 libnvme-spec.a $(libdir)/libnvme-spec.a
	for i in $(libnvme_api); do $(INSTALL) -D -m 644 $$i $(includedir)/$$i; done
	for i in $(libnvme_spec_api); do $(INSTALL) -D -m 644 $$i $(includedir)/$$i; done
ifeq ($(ENABLE_SHARED),1)
	$(INSTALL) -D -m 755 $(libnvme_name) $(libdir)/$(libnvme_name)
	ln -sf $(libnvme_name) $(libdir)/$(libnvme_soname)
	ln -sf $(libnvme_name) $(libdir)/libnvme.so
	$(INSTALL) -D -m 755 $(libnvme_spec_name) $(libdir)/$(libnvme_spec_name)
	ln -sf $(libnvme_spec_name) $(libdir)/$(libnvme_spec_soname)
	ln -sf $(libnvme_spec_name) $(libdir)/libnvme-spec.so
endif

$(libnvme_objs): $(libnvme_api) $(libnvme_private)
$(libnvme_spec_objs): $(libnvme_spec_api)
$(libccan_objs): $(libccan_headers) $(CCANDIR)config.h

clean:
	rm -f $(all_targets)
	rm -f $(libccan_objs) $(libccan_sobjs)
	rm -f $(libnvme_objs) $(libnvme_sobjs) $(libnvme_soname).new
	rm -f $(libnvme_spec_objs) $(libnvme_spec_sobjs) $(libnvme_spec_soname).new
	rm -f $(CCANDIR)config.h
	rm -f $(CCANDIR)tools/configurator/configurator
	rm -f *.so* *.a *.o
