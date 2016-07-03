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

#include <linux/errno.h>
#include <linux/fs.h>
#include <linux/genetlink.h>
#include <linux/if_ether.h>
#include <linux/init.h>
#include <linux/netdevice.h>
#include <linux/netlink.h>
#include <linux/printk.h>
#include <linux/rculist.h>
#include <linux/rcupdate.h>
#include <linux/skbuff.h>
#include <linux/stddef.h>
#include <linux/types.h>
#include <net/genetlink.h>
#include <net/netlink.h>
#include <net/sock.h>
#include "uapi/linux/batman_adv.h"

#include "bat_algo.h"
#include "hard-interface.h"
#include "soft-interface.h"

struct genl_family batadv_netlink_family;

static struct nla_policy batadv_netlink_policy[NUM_BATADV_ATTR] = {
	[BATADV_ATTR_VERSION]		= { .type = NLA_STRING },
	[BATADV_ATTR_ALGO_NAME]		= { .type = NLA_STRING },
	[BATADV_ATTR_MESH_IFINDEX]	= { .type = NLA_U32 },
	[BATADV_ATTR_MESH_IFNAME]	= { .type = NLA_STRING },
	[BATADV_ATTR_MESH_ADDRESS]	= { .len = ETH_ALEN },
	[BATADV_ATTR_HARD_IFINDEX]	= { .type = NLA_U32 },
	[BATADV_ATTR_HARD_IFNAME]	= { .type = NLA_STRING },
	[BATADV_ATTR_HARD_ADDRESS]	= { .len = ETH_ALEN },
	[BATADV_ATTR_ORIG_ADDRESS]	= { .len = ETH_ALEN },
	[BATADV_ATTR_TPMETER_RESULT]	= { .type = NLA_U8 },
	[BATADV_ATTR_TPMETER_TEST_TIME]	= { .type = NLA_U32 },
	[BATADV_ATTR_TPMETER_BYTES]	= { .type = NLA_U64 },
	[BATADV_ATTR_TPMETER_COOKIE]	= { .type = NLA_U32 },
	[BATADV_ATTR_ACTIVE]		= { .type = NLA_FLAG },
};

/**
 * batadv_netlink_get_ifindex - Extract an interface index from a message
 * @nlh: Message header
 * @attrtype: Attribute which holds an interface index
 *
 * Return: interface index, or 0.
 */
static int
batadv_netlink_get_ifindex(const struct nlmsghdr *nlh, int attrtype)
{
	struct nlattr *attr = nlmsg_find_attr(nlh, GENL_HDRLEN, attrtype);

	return attr ? nla_get_u32(attr) : 0;
}

/**
 * batadv_netlink_mesh_info_put - fill in generic information about mesh
 *  interface
 * @msg: netlink message to be sent back
 * @soft_iface: interface for which the data should be taken
 *
 * Return: 0 on success, < 0 on error
 */
static int
batadv_netlink_mesh_info_put(struct sk_buff *msg, struct net_device *soft_iface)
{
	struct batadv_priv *bat_priv = netdev_priv(soft_iface);
	struct batadv_hard_iface *primary_if = NULL;
	struct net_device *hard_iface;
	int ret = -ENOBUFS;

	if (nla_put_string(msg, BATADV_ATTR_VERSION, BATADV_SOURCE_VERSION) ||
	    nla_put_string(msg, BATADV_ATTR_ALGO_NAME,
			   bat_priv->bat_algo_ops->name) ||
	    nla_put_u32(msg, BATADV_ATTR_MESH_IFINDEX, soft_iface->ifindex) ||
	    nla_put_string(msg, BATADV_ATTR_MESH_IFNAME, soft_iface->name) ||
	    nla_put(msg, BATADV_ATTR_MESH_ADDRESS, ETH_ALEN,
		    soft_iface->dev_addr))
		goto out;

	primary_if = batadv_primary_if_get_selected(bat_priv);
	if (primary_if && primary_if->if_status == BATADV_IF_ACTIVE) {
		hard_iface = primary_if->net_dev;

		if (nla_put_u32(msg, BATADV_ATTR_HARD_IFINDEX,
				hard_iface->ifindex) ||
		    nla_put_string(msg, BATADV_ATTR_HARD_IFNAME,
				   hard_iface->name) ||
		    nla_put(msg, BATADV_ATTR_HARD_ADDRESS, ETH_ALEN,
			    hard_iface->dev_addr))
			goto out;
	}

	ret = 0;

 out:
	if (primary_if)
		batadv_hardif_free_ref(primary_if);

	return ret;
}

/**
 * batadv_netlink_get_mesh_info - handle incoming BATADV_CMD_GET_MESH_INFO
 *  netlink request
 * @skb: received netlink message
 * @info: receiver information
 *
 * Return: 0 on success, < 0 on error
 */
static int
batadv_netlink_get_mesh_info(struct sk_buff *skb, struct genl_info *info)
{
	struct net *net = genl_info_net(info);
	struct net_device *soft_iface;
	struct sk_buff *msg = NULL;
	void *msg_head;
	int ifindex;
	int ret;

	if (!info->attrs[BATADV_ATTR_MESH_IFINDEX])
		return -EINVAL;

	ifindex = nla_get_u32(info->attrs[BATADV_ATTR_MESH_IFINDEX]);
	if (!ifindex)
		return -EINVAL;

	soft_iface = dev_get_by_index(net, ifindex);
	if (!soft_iface || !batadv_softif_is_valid(soft_iface)) {
		ret = -ENODEV;
		goto out;
	}

	msg = nlmsg_new(NLMSG_DEFAULT_SIZE, GFP_KERNEL);
	if (!msg) {
		ret = -ENOMEM;
		goto out;
	}

	msg_head = genlmsg_put(msg, info->snd_portid, info->snd_seq,
			       &batadv_netlink_family, 0,
			       BATADV_CMD_GET_MESH_INFO);
	if (!msg_head) {
		ret = -ENOBUFS;
		goto out;
	}

	ret = batadv_netlink_mesh_info_put(msg, soft_iface);

 out:
	if (soft_iface)
		dev_put(soft_iface);

	if (ret) {
		if (msg)
			nlmsg_free(msg);
		return ret;
	}

	genlmsg_end(msg, msg_head);
	return genlmsg_reply(msg, info);
}

/**
 * batadv_netlink_dump_hardif_entry - Dump one hard interface into a message
 * @msg: Netlink message to dump into
 * @portid: Port making netlink request
 * @seq: Sequence number of netlink message
 * @hard_iface: Hard interface to dump
 *
 * Return: error code, or 0 on success
 */
static int
batadv_netlink_dump_hardif_entry(struct sk_buff *msg, u32 portid, u32 seq,
				 struct batadv_hard_iface *hard_iface)
{
	struct net_device *net_dev = hard_iface->net_dev;
	void *hdr;

	hdr = genlmsg_put(msg, portid, seq, &batadv_netlink_family, NLM_F_MULTI,
			  BATADV_CMD_GET_HARDIFS);
	if (!hdr)
		return -EMSGSIZE;

	if (nla_put_u32(msg, BATADV_ATTR_HARD_IFINDEX,
			net_dev->ifindex) ||
	    nla_put_string(msg, BATADV_ATTR_HARD_IFNAME,
			   net_dev->name) ||
	    nla_put(msg, BATADV_ATTR_HARD_ADDRESS, ETH_ALEN,
		    net_dev->dev_addr))
		goto nla_put_failure;

	if (hard_iface->if_status == BATADV_IF_ACTIVE) {
		if (nla_put_flag(msg, BATADV_ATTR_ACTIVE))
			goto nla_put_failure;
	}

	genlmsg_end(msg, hdr);
	return 0;

 nla_put_failure:
	genlmsg_cancel(msg, hdr);
	return -EMSGSIZE;
}

/**
 * batadv_netlink_dump_hardifs - Dump all hard interface into a messages
 * @msg: Netlink message to dump into
 * @cb: Parameters from query
 *
 * Return: error code, or length of reply message on success
 */
static int
batadv_netlink_dump_hardifs(struct sk_buff *msg, struct netlink_callback *cb)
{
	struct net *net = sock_net(cb->skb->sk);
	struct net_device *soft_iface;
	struct batadv_hard_iface *hard_iface;
	int ifindex;
	int portid = NETLINK_CB(cb->skb).portid;
	int seq = cb->nlh->nlmsg_seq;
	int skip = cb->args[0];
	int i = 0;

	ifindex = batadv_netlink_get_ifindex(cb->nlh,
					     BATADV_ATTR_MESH_IFINDEX);
	if (!ifindex)
		return -EINVAL;

	soft_iface = dev_get_by_index(net, ifindex);
	if (!soft_iface)
		return -ENODEV;

	if (!batadv_softif_is_valid(soft_iface)) {
		dev_put(soft_iface);
		return -ENODEV;
	}

	rcu_read_lock();

	list_for_each_entry_rcu(hard_iface, &batadv_hardif_list, list) {
		if (hard_iface->soft_iface != soft_iface)
			continue;

		if (i++ < skip)
			continue;

		if (batadv_netlink_dump_hardif_entry(msg, portid, seq,
						     hard_iface)) {
			i--;
			break;
		}
	}

	rcu_read_unlock();

	dev_put(soft_iface);

	cb->args[0] = i;

	return msg->len;
}

static __genl_const struct genl_ops batadv_netlink_ops[] = {
	{
		.cmd = BATADV_CMD_GET_MESH_INFO,
		.flags = GENL_ADMIN_PERM,
		.policy = batadv_netlink_policy,
		.doit = batadv_netlink_get_mesh_info,
	},
	{
		.cmd = BATADV_CMD_GET_ROUTING_ALGOS,
		.flags = GENL_ADMIN_PERM,
		.policy = batadv_netlink_policy,
		.dumpit = batadv_algo_dump,
	},
	{
		.cmd = BATADV_CMD_GET_HARDIFS,
		.flags = GENL_ADMIN_PERM,
		.policy = batadv_netlink_policy,
		.dumpit = batadv_netlink_dump_hardifs,
	},
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
