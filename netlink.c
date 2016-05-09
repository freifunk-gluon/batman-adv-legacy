/* Copyright (C) 2016 B.A.T.M.A.N. contributors:
 *
 * Matthias Schiffer
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

#include "main.h"
#include "netlink.h"

#include <linux/genetlink.h>
#include <linux/init.h>
#include <linux/printk.h>
#include <net/genetlink.h>
#include "uapi/linux/batman_adv.h"

struct genl_family batadv_netlink_family;

static __genl_const struct genl_ops batadv_netlink_ops[] = {
};

static __genl_const struct genl_multicast_group batadv_netlink_mcgrps[] = {
};

struct genl_family batadv_netlink_family __ro_after_init = {
	.hdrsize = 0,
	.name = BATADV_NL_NAME,
	.version = 1,
	.maxattr = BATADV_ATTR_MAX,
	.netnsok = true,
	.module = THIS_MODULE,
	.ops = batadv_netlink_ops,
	.n_ops = ARRAY_SIZE(batadv_netlink_ops),
	.mcgrps = batadv_netlink_mcgrps,
	.n_mcgrps = ARRAY_SIZE(batadv_netlink_mcgrps),
};

/**
 * batadv_netlink_register - register batadv genl netlink family
 */
void __init batadv_netlink_register(void)
{
	int ret;

	ret = genl_register_family(&batadv_netlink_family);
	if (ret)
		pr_warn("unable to register netlink family");
}

/**
 * batadv_netlink_unregister - unregister batadv genl netlink family
 */
void batadv_netlink_unregister(void)
{
	genl_unregister_family(&batadv_netlink_family);
}
