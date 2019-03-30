/* Copyright (C) 2007-2013 B.A.T.M.A.N. contributors:
 *
 * Marek Lindner, Simon Wunderlich
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
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA
 *
 *
 * This file contains macros for maintaining compatibility with older versions
 * of the Linux kernel.
 */

#ifndef _NET_BATMAN_ADV_COMPAT_H_
#define _NET_BATMAN_ADV_COMPAT_H_

#include <linux/version.h>	/* LINUX_VERSION_CODE */

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 30)

#undef __alloc_percpu
#define __alloc_percpu(size, align) \
	percpu_alloc_mask((size), GFP_KERNEL, cpu_possible_map)

#endif /* < KERNEL_VERSION(2, 6, 30) */


#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 31)

#define __compat__module_param_call(p1, p2, p3, p4, p5, p6, p7) \
	__module_param_call(p1, p2, p3, p4, p5, p7)

#else

#define __compat__module_param_call(p1, p2, p3, p4, p5, p6, p7) \
	__module_param_call(p1, p2, p3, p4, p5, p6, p7)

#endif /* < KERNEL_VERSION(2, 6, 31) */


#if (LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 33))
#include <linux/autoconf.h>
#else
#include <generated/autoconf.h>
#endif
#include "compat-autoconf.h"

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 33)

#define __always_unused			__attribute__((unused))
#define __percpu

#define skb_iif iif

#define this_cpu_add(x, c)	batadv_this_cpu_add(&(x), c)

static inline void batadv_this_cpu_add(uint64_t *count_ptr, size_t count)
{
	int cpu = get_cpu();
	*per_cpu_ptr(count_ptr, cpu) += count;
	put_cpu();
}

#define batadv_softif_destroy_netlink(dev, head) batadv_softif_destroy_netlink(dev)
#define unregister_netdevice_queue(dev, head) unregister_netdevice(dev)

static inline struct sk_buff *netdev_alloc_skb_ip_align(struct net_device *dev,
							unsigned int length)
{
	struct sk_buff *skb = netdev_alloc_skb(dev, length + NET_IP_ALIGN);

	if (NET_IP_ALIGN && skb)
		skb_reserve(skb, NET_IP_ALIGN);
	return skb;
}

#endif /* < KERNEL_VERSION(2, 6, 33) */


#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 34)

#define rcu_dereference_protected(p, c) (p)

#define rcu_dereference_raw(p)	({ \
				 typeof(p) _________p1 = ACCESS_ONCE(p); \
				 smp_read_barrier_depends(); \
				 (_________p1); \
				 })

#endif /* < KERNEL_VERSION(2, 6, 34) */

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 35)

#define pr_warn pr_warning

#endif /* < KERNEL_VERSION(2, 6, 35) */


#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 36)

#define __rcu
#define IFF_BRIDGE_PORT  0 || (hard_iface->net_dev->br_port ? 1 : 0)

struct kernel_param_ops {
	/* Returns 0, or -errno.  arg is in kp->arg. */
	int (*set)(const char *val, const struct kernel_param *kp);
	/* Returns length written or -errno.  Buffer is 4k (ie. be short!) */
	int (*get)(char *buffer, struct kernel_param *kp);
	/* Optional function to free kp->arg when module unloaded. */
	void (*free)(void *arg);
};

#define module_param_cb(name, ops, arg, perm)				\
	static int __compat_set_param_##name(const char *val,		\
					     struct kernel_param *kp)	\
				{ return (ops)->set(val, kp); }		\
	static int __compat_get_param_##name(char *buffer,		\
					     struct kernel_param *kp)	\
				{ return (ops)->get(buffer, kp); }	\
	__compat__module_param_call(MODULE_PARAM_PREFIX, name,		\
				    __compat_set_param_##name,		\
				    __compat_get_param_##name, arg,	\
				    __same_type((arg), bool *), perm)

static inline int batadv_param_set_copystring(const char *val,
					      const struct kernel_param *kp)
{
	return param_set_copystring(val, (struct kernel_param *)kp);
}
#define param_set_copystring batadv_param_set_copystring

/* hack for dev->addr_assign_type &= ~NET_ADDR_RANDOM; */
#define addr_assign_type ifindex
#define NET_ADDR_RANDOM 0

#endif /* < KERNEL_VERSION(2, 6, 36) */

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 37)

#define hlist_first_rcu(head)	(*((struct hlist_node __rcu **)(&(head)->first)))
#define hlist_next_rcu(node)	(*((struct hlist_node __rcu **)(&(node)->next)))

#endif /* < KERNEL_VERSION(2, 6, 37) */

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 39)

#define kstrtoul strict_strtoul
#define kstrtol  strict_strtol

/* Hack for removing ndo_add/del_slave at the end of net_device_ops.
 * This is somewhat ugly because it requires that ndo_validate_addr
 * is at the end of this struct in soft-interface.c.
 */
#define ndo_validate_addr \
	ndo_validate_addr = eth_validate_addr, \
}; \
static const struct { \
	void *ndo_validate_addr; \
	void *ndo_add_slave; \
	void *ndo_del_slave; \
} __attribute__((unused)) __useless_ops1 = { \
	.ndo_validate_addr

#define ndo_del_slave          ndo_init
#define ndo_init(x, y)         ndo_init - master->netdev_ops->ndo_init - EBUSY

#endif /* < KERNEL_VERSION(2, 6, 39) */


#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 0, 0)

#define kfree_rcu(ptr, rcu_head) call_rcu(&ptr->rcu_head, batadv_free_rcu_##ptr)
#define vlan_insert_tag(skb, proto, vid) __vlan_put_tag(skb, vid)

void batadv_free_rcu_gw_node(struct rcu_head *rcu);
void batadv_free_rcu_neigh_node(struct rcu_head *rcu);
void batadv_free_rcu_tt_local_entry(struct rcu_head *rcu);
void batadv_free_rcu_backbone_gw(struct rcu_head *rcu);
void batadv_free_rcu_dat_entry(struct rcu_head *rcu);
void batadv_free_rcu_nc_path(struct rcu_head *rcu);

static inline void skb_reset_mac_len(struct sk_buff *skb)
{
	skb->mac_len = skb->network_header - skb->mac_header;
}

#endif /* < KERNEL_VERSION(3, 0, 0) */


#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 4, 0)

#define eth_hw_addr_random(dev)	batadv_eth_hw_addr_random(dev)

static inline void batadv_eth_hw_addr_random(struct net_device *dev)
{
	random_ether_addr(dev->dev_addr);
}

#endif /* < KERNEL_VERSION(3, 4, 0) */

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 5, 0)

#ifndef net_ratelimited_function
#define net_ratelimited_function(func, ...) \
	do { \
		if (net_ratelimit()) \
			func(__VA_ARGS__); \
	} while (0)
#endif /* ifndef net_ratelimited_function */

static inline int nla_put_be32(struct sk_buff *skb, int attrtype, __be32 value)
{
	__be32 tmp = value;

	return nla_put(skb, attrtype, sizeof(__be32), &tmp);
}

#endif /* < KERNEL_VERSION(3, 5, 0) */

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 7, 0)

#define snd_portid snd_pid

#include <net/scm.h>

struct batadv_netlink_skb_parms {
	struct ucred		creds;		/* Skb credentials	*/
	union {
		__u32		portid;
		__u32		pid;
	};
	__u32			dst_group;
};

#undef NETLINK_CB
#define NETLINK_CB(skb) (*(struct batadv_netlink_skb_parms *)&((skb)->cb))

#endif /* < KERNEL_VERSION(3, 7, 0) */

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 8, 0)

#define ETH_P_BATMAN	0x4305

/* hack for not correctly set mac_len. This may happen for some special
 * configurations like batman-adv on VLANs.
 *
 * This is pretty dirty, but we only use skb_share_check() in main.c right
 * before mac_len is checked, and the recomputation shouldn't hurt too much.
 */
#define skb_share_check(skb, b) \
	({ \
		struct sk_buff *_t_skb; \
		_t_skb = skb_share_check(skb, b); \
		if (_t_skb) \
			skb_reset_mac_len(_t_skb); \
		_t_skb; \
	})

#endif /* < KERNEL_VERSION(3, 8, 0) */

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 9, 0)

#define prandom_u32() random32()

#define batadv_interface_set_mac_addr(x, y) \
__batadv_interface_set_mac_addr(struct net_device *dev, void *p);\
static int batadv_interface_set_mac_addr(struct net_device *dev, void *p) \
{\
	int ret;\
\
	ret = __batadv_interface_set_mac_addr(dev, p);\
	if (!ret) \
		dev->addr_assign_type &= ~NET_ADDR_RANDOM;\
	return ret;\
}\
static int __batadv_interface_set_mac_addr(x, y)

#define netdev_upper_dev_unlink(slave, master) netdev_set_master(slave, NULL)
#define netdev_master_upper_dev_get(dev) \
({\
	ASSERT_RTNL();\
	dev->master;\
})
#define hlist_entry_safe(ptr, type, member) \
	({ typeof(ptr) ____ptr = (ptr); \
	   ____ptr ? hlist_entry(____ptr, type, member) : NULL; \
	})

#undef hlist_for_each_entry
#define hlist_for_each_entry(pos, head, member) \
	for (pos = hlist_entry_safe((head)->first, typeof(*(pos)), member);\
	pos; \
	pos = hlist_entry_safe((pos)->member.next, typeof(*(pos)), member))

#undef hlist_for_each_entry_rcu
#define hlist_for_each_entry_rcu(pos, head, member) \
	for (pos = hlist_entry_safe (rcu_dereference_raw(hlist_first_rcu(head)),\
	typeof(*(pos)), member); \
	pos; \
	pos = hlist_entry_safe(rcu_dereference_raw(hlist_next_rcu(\
	&(pos)->member)), typeof(*(pos)), member))

#undef hlist_for_each_entry_safe
#define hlist_for_each_entry_safe(pos, n, head, member) \
	for (pos = hlist_entry_safe((head)->first, typeof(*pos), member);\
	pos && ({ n = pos->member.next; 1; }); \
	pos = hlist_entry_safe(n, typeof(*pos), member))

#endif /* < KERNEL_VERSION(3, 9, 0) */

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 10, 0)

#ifndef vlan_insert_tag

/* include this header early to let the following define
 * not mess up the original function prototype.
 */
#include <linux/if_vlan.h>
#define vlan_insert_tag(skb, proto, vid) vlan_insert_tag(skb, vid)

#endif /* vlan_insert_tag */

#endif /* < KERNEL_VERSION(3, 10, 0) */

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 11, 0)

#define netdev_notifier_info_to_dev(ptr) ptr

/* older kernels still need to call skb_abort_seq_read() */
#define skb_seq_read(consumed, data, st) \
	({ \
		int __len = skb_seq_read(consumed, data, st); \
		if (__len == 0) \
			skb_abort_seq_read(st); \
		__len; \
	})
#endif /* < KERNEL_VERSION(3, 11, 0) */

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 13, 0)

#include_next <net/genetlink.h>
#include <linux/export.h>

struct batadv_genl_family {
	/* data handled by the actual kernel */
	struct genl_family family;

	/* data which has to be copied to family by
	 * batadv_genlmsg_multicast_netns
	 */
	unsigned int		id;
	unsigned int		hdrsize;
	char			name[GENL_NAMSIZ];
	unsigned int		version;
	unsigned int		maxattr;
	bool			netnsok;
	bool			parallel_ops;
	int			(*pre_doit)(struct genl_ops *ops,
					    struct sk_buff *skb,
					    struct genl_info *info);
	void			(*post_doit)(struct genl_ops *ops,
					     struct sk_buff *skb,
					     struct genl_info *info);
	/* WARNING not supported
	 * int			(*mcast_bind)(struct net *net, int group);
	 * void			(*mcast_unbind)(struct net *net, int group);
	 */
	struct nlattr		**attrbuf;	/* private */
	struct genl_ops		*ops;		/* private */
	struct genl_multicast_group *mcgrps; /* private */
	unsigned int		n_ops;		/* private */
	unsigned int		n_mcgrps;	/* private */
	/* unsigned int		mcgrp_offset;	private, WARNING unsupported */
	struct list_head	family_list;	/* private */
	struct module		*module;
};

#define genl_family batadv_genl_family

#define genlmsg_multicast_netns batadv_genlmsg_multicast_netns

static inline int
batadv_genlmsg_multicast_netns(struct batadv_genl_family *family,
			       struct net *net,
			       struct sk_buff *skb,
			       u32 portid, unsigned int group,
			       gfp_t flags)
{
	group = family->mcgrps[group].id;
	return nlmsg_multicast(
		net->genl_sock,
		skb, portid, group, flags);
}

#define genlmsg_put(_skb, _pid, _seq, _family, _flags, _cmd) \
	genlmsg_put(_skb, _pid, _seq, &(_family)->family, _flags, _cmd)

#define genl_unregister_family(_family) \
	genl_unregister_family(&(_family)->family)

static inline int batadv_genl_register_family(struct genl_family *family)
{
	unsigned int i;
	int ret;

	family->family.id = family->id;
	family->family.hdrsize = family->hdrsize;
	strncpy(family->family.name, family->name, sizeof(family->family.name));
	family->family.version = family->version;
	family->family.maxattr = family->maxattr;
	family->family.netnsok = family->netnsok;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 10, 0)
	family->family.parallel_ops = family->parallel_ops;
#endif
	family->family.pre_doit = family->pre_doit;
	family->family.post_doit = family->post_doit;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 11, 0)
	family->family.module = family->module;
#endif

	ret = genl_register_family(&family->family);
	if (ret < 0)
		return ret;

	family->attrbuf = family->family.attrbuf;
	family->id = family->family.id;

	for (i = 0; i < family->n_ops; i++) {
		ret = genl_register_ops(&family->family, &family->ops[i]);
		if (ret < 0)
			goto err;
	}

	for (i = 0; i < family->n_mcgrps; i++) {
		ret = genl_register_mc_group(&family->family,
					     &family->mcgrps[i]);
		if (ret)
			goto err;
	}

	return 0;

 err:
	genl_unregister_family(family);
	return ret;
}

#define genl_register_family(family) \
	batadv_genl_register_family((family))

#define __genl_const

#else

#define __genl_const const

#endif /* < KERNEL_VERSION(3, 13, 0) */

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 17, 0)

/* alloc_netdev() was defined differently before 2.6.38 */
#undef alloc_netdev
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 38)
#define alloc_netdev(sizeof_priv, name, name_assign_type, setup) \
	alloc_netdev_mq(sizeof_priv, name, setup, 1)
#else
#define alloc_netdev(sizeof_priv, name, name_assign_type, setup) \
	alloc_netdev_mqs(sizeof_priv, name, setup, 1, 1)
#endif /* nested < KERNEL_VERSION(2, 6, 38) */

#endif /* < KERNEL_VERSION(3, 17, 0) */

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 19, 0)

static inline bool seq_has_overflowed(struct seq_file *m)
{
	return m->count == m->size;
}

#endif /* < KERNEL_VERSION(3, 19, 0) */

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 1, 0)

#define dev_get_iflink(_net_dev) ((_net_dev)->iflink)

static inline int nla_put_in_addr(struct sk_buff *skb, int attrtype,
				  __be32 addr)
{
	__be32 tmp = addr;

	return nla_put_be32(skb, attrtype, tmp);
}

#endif /* < KERNEL_VERSION(4, 1, 0) */

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 9, 0)

#define netdev_master_upper_dev_link(dev, upper_dev, upper_priv, upper_info, extack) \
	netdev_set_master(dev, upper_dev)

#elif LINUX_VERSION_CODE < KERNEL_VERSION(4, 5, 0)

#define netdev_master_upper_dev_link(dev, upper_dev, upper_priv, upper_info, extack) \
	netdev_master_upper_dev_link(dev, upper_dev)

#elif LINUX_VERSION_CODE < KERNEL_VERSION(4, 15, 0)

#define netdev_master_upper_dev_link(dev, upper_dev, upper_priv, upper_info, extack) \
	netdev_master_upper_dev_link(dev, upper_dev, upper_priv, upper_info)

#endif /* < KERNEL_VERSION(4, 15, 0) */

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 6, 0)

#define __ro_after_init

#endif /* < KERNEL_VERSION(4, 10, 0) */

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 7, 0)

#define netif_trans_update batadv_netif_trans_update
static inline void batadv_netif_trans_update(struct net_device *dev)
{
	dev->trans_start = jiffies;
}

#endif /* < KERNEL_VERSION(4, 7, 0) */

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 12, 0)

/* work around missing attribute needs_free_netdev and priv_destructor in
 * net_device
 */
#define ether_setup(dev) \
	void batadv_softif_free2(struct net_device *dev) \
	{ \
		batadv_softif_free(dev); \
		free_netdev(dev); \
	} \
	void (*t1)(struct net_device *dev) __attribute__((unused)); \
	bool t2 __attribute__((unused)); \
	ether_setup(dev)
#define needs_free_netdev destructor = batadv_softif_free2; t2
#define priv_destructor destructor = batadv_softif_free2; t1

#endif /* < KERNEL_VERSION(4, 12, 0) */

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 15, 0)

#define batadv_softif_slave_add(__dev, __slave_dev, __extack) \
	batadv_softif_slave_add(__dev, __slave_dev)

#endif /* < KERNEL_VERSION(4, 15, 0) */

#include <linux/uaccess.h>

#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 0, 0)

static inline int batadv_access_ok(int type, const void __user *p,
				   unsigned long size)
{
	return access_ok(type, p, size);
}

#ifdef access_ok
#undef access_ok
#endif

#define access_ok_get(_1, _2, _3 , access_ok_name, ...) access_ok_name
#define access_ok(...) \
	access_ok_get(__VA_ARGS__, access_ok3, access_ok2)(__VA_ARGS__)

#define access_ok2(addr, size) batadv_access_ok(VERIFY_WRITE, (addr), (size))
#define access_ok3(type, addr, size)   batadv_access_ok((type), (addr), (size))

#endif /* < KERNEL_VERSION(5, 0, 0) */


#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 2, 0)

struct batadv_genl_family {
	/* data handled by the actual kernel */
	struct genl_family family;

	/* data which has to be copied to family by
	 * batadv_genl_register_family
	 */
	unsigned int hdrsize;
	char name[GENL_NAMSIZ];
	unsigned int version;
	unsigned int maxattr;
	const struct nla_policy *policy;
	bool netnsok;
	int  (*pre_doit)(const struct genl_ops *ops, struct sk_buff *skb,
			 struct genl_info *info);
	void (*post_doit)(const struct genl_ops *ops, struct sk_buff *skb,
			  struct genl_info *info);
	const struct genl_ops *ops;
	const struct genl_multicast_group *mcgrps;
	unsigned int n_ops;
	unsigned int n_mcgrps;
	struct module *module;

	/* allocated by batadv_genl_register_family and free'd by
	 * batadv_genl_unregister_family. Used to modify the usually read-only
	 * ops
	 */
	struct genl_ops *copy_ops;
};

#define genl_family batadv_genl_family

static inline int batadv_genl_register_family(struct batadv_genl_family *family)
{
	struct genl_ops *ops;
	unsigned int i;

	family->family.hdrsize = family->hdrsize;
	strncpy(family->family.name, family->name, sizeof(family->family.name));
	family->family.version = family->version;
	family->family.maxattr = family->maxattr;
	family->family.netnsok = family->netnsok;
	family->family.pre_doit = family->pre_doit;
	family->family.post_doit = family->post_doit;
	family->family.mcgrps = family->mcgrps;
	family->family.n_ops = family->n_ops;
	family->family.n_mcgrps = family->n_mcgrps;
	family->family.module = family->module;

	ops = kmemdup(family->ops, sizeof(*ops) * family->n_ops, GFP_KERNEL);
	if (!ops)
		return -ENOMEM;

	for (i = 0; i < family->family.n_ops; i++)
		ops[i].policy = family->policy;

	family->family.ops = ops;
	family->copy_ops = ops;

	return genl_register_family(&family->family);
}

#define genl_register_family(family) \
	batadv_genl_register_family((family))

static inline void
batadv_genl_unregister_family(struct batadv_genl_family *family)
{

	genl_unregister_family(&family->family);
	kfree(family->copy_ops);
}

#define genl_unregister_family(family) \
	batadv_genl_unregister_family((family))

#define genlmsg_put(_skb, _pid, _seq, _family, _flags, _cmd) \
	genlmsg_put(_skb, _pid, _seq, &(_family)->family, _flags, _cmd)

#define genlmsg_multicast_netns(_family, _net, _skb, _portid, _group, _flags) \
	genlmsg_multicast_netns(&(_family)->family, _net, _skb, _portid, \
				_group, _flags)

#endif /* < KERNEL_VERSION(5, 2, 0) */

#endif /* _NET_BATMAN_ADV_COMPAT_H_ */
