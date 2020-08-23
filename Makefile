#
# Copyright (C) 2007-2013 B.A.T.M.A.N. contributors:
#
# Marek Lindner, Simon Wunderlich
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of version 2 of the GNU General Public
# License as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
# 02110-1301, USA
#

# read README.external for more information about the configuration
# B.A.T.M.A.N. debugging:
export CONFIG_BATMAN_ADV_DEBUG=n
# B.A.T.M.A.N. bridge loop avoidance:
export CONFIG_BATMAN_ADV_BLA=y
# B.A.T.M.A.N. distributed ARP table:
export CONFIG_BATMAN_ADV_DAT=y
# B.A.T.M.A.N network coding (catwoman):
export CONFIG_BATMAN_ADV_NC=n

PWD:=$(shell pwd)
KERNELPATH ?= /lib/modules/$(shell uname -r)/build
# sanity check: does KERNELPATH exist?
ifeq ($(shell cd $(KERNELPATH) && pwd),)
$(warning $(KERNELPATH) is missing, please set KERNELPATH)
endif

OBJCOPY ?= objcopy
OBJDUMP ?= objdump

export KERNELPATH
RM ?= rm -f
RMDIR ?= rm -rf

REVISION= $(shell	if [ -d "$(PWD)/.git" ]; then \
				echo $$(git --git-dir="$(PWD)/.git" describe --always --dirty --match "v*" |sed 's/^v//' 2> /dev/null || echo "[unknown]"); \
			fi)

CONFIG_BATMAN_ADV=m
batman-adv-legacy-y += compat.o
ifneq ($(REVISION),)
ccflags-y += -DBATADV_SOURCE_VERSION=\"$(REVISION)\"
endif
include $(PWD)/Makefile.kbuild

all: batman-adv-legacy.ko

build:
	mkdir -p "$@"

build/Makefile: build
	touch "$@"

build/batman-adv-legacy.ko: config build/Makefile
	$(MAKE) -C $(KERNELPATH) M=$(PWD)/build PWD=$(PWD) src=$(PWD) modules

build/updated-syms.txt: build/batman-adv-legacy.ko
	$(OBJDUMP) -t $(PWD)/build/batman-adv-legacy.ko | grep batadv_ | \
		sed "s/.* \([^ ]*\)batadv_\([^ ]*\)$$/\1batadv_\2 \1batadv_legacy_\2/" | \
			sort | uniq > $(PWD)/build/updated-syms.txt

batman-adv-legacy.ko: build/batman-adv-legacy.ko build/updated-syms.txt
	$(OBJCOPY) --redefine-syms=$(PWD)/build/updated-syms.txt $(PWD)/build/batman-adv-legacy.ko $(PWD)/batman-adv-legacy.ko

clean:
	$(RM) compat-autoconf.h*
	$(RMDIR) build
	$(MAKE) -C $(KERNELPATH) M=$(PWD) PWD=$(PWD) clean

install: config
	$(MAKE) -C $(KERNELPATH) M=$(PWD) PWD=$(PWD) INSTALL_MOD_DIR=updates/net/batman-adv/ modules_install
	depmod -a

config:
	$(PWD)/gen-compat-autoconf.sh $(PWD)/compat-autoconf.h

.PHONY: all clean install config
