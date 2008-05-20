/*
 * Copyright (C) 2008 B.A.T.M.A.N. contributors:
 * Simon Wunderlich
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
 */





#include "main.h"
#include "send.h"
#include "translation-table.h"
#include "vis.h"
#include "log.h"
#include "soft-interface.h"
#include "hard-interface.h"
#include "hash.h"



struct hashtable_t *vis_hash;
DEFINE_SPINLOCK(vis_hash_lock);
static struct vis_info *my_vis_info = NULL;
static struct list_head send_list;	/* always locked with vis_hash_lock ... */
static struct timer_list vis_timer;

void free_info(void *data);
void send_vis_packet(struct vis_info *info);
void start_vis_timer(void);


int vis_info_cmp(void *data1, void *data2) {
	struct vis_info *d1, *d2;
	d1 = data1;
	d2 = data2;
	return(memcmp(d1->packet.vis_orig, d2->packet.vis_orig, ETH_ALEN) == 0);
}

/* hashfunction to choose an entry in a hash table of given size */
/* hash algorithm from http://en.wikipedia.org/wiki/Hash_table */
int vis_info_choose(void *data, int size) {
	struct vis_info *vis_info = data;
	unsigned char *key;
	uint32_t hash = 0;
	size_t i;

	key = vis_info->packet.vis_orig;
	for (i = 0; i < ETH_ALEN; i++) {
		hash += key[i];
		hash += (hash << 10);
		hash ^= (hash >> 6);
	}

	hash += (hash << 3);
	hash ^= (hash >> 11);
	hash += (hash << 15);

	return (hash%size);
}

/* tries to add one entry to the receive list. */
void recv_list_add(struct list_head *recv_list, char *mac)
{
	struct recvlist_node *entry;
	entry = kmalloc(sizeof(struct recvlist_node), GFP_KERNEL);
	if (!entry)
		return;

	memcpy(entry->mac, mac, ETH_ALEN);
	list_add_tail(&entry->list, recv_list);
}

/* returns 1 if this mac is in the recv_list */
int recv_list_is_in(struct list_head *recv_list, char *mac)
{
	struct recvlist_node *entry;

	list_for_each_entry(entry, recv_list, list) {

		if (memcmp(entry->mac, mac, ETH_ALEN) == 0)
			return 1;
	}

	return 0;
}

/* try to add the packet to the vis_hash. return NULL if invalid (e.g. too old, broken.. ).
 * vis hash must be locked outside.
 * is_new is set when the packet is newer than old entries in the hash. */

struct vis_info *add_packet(struct vis_packet *vis_packet, int vis_info_len, int *is_new)
{
	struct vis_info *info, *old_info;
	struct vis_info search_elem;

	*is_new = 0;
	/* sanity check */
	if (vis_hash == NULL)
		return NULL;

	/* see if the packet is already in vis_hash */
	memcpy(search_elem.packet.vis_orig, vis_packet->vis_orig, ETH_ALEN);
	old_info = hash_find(vis_hash, &search_elem);

	if (old_info != NULL) {
		if (vis_packet->seqno - old_info->packet.seqno <= 0) {
			if (old_info->packet.seqno == vis_packet->seqno) {

				recv_list_add(&old_info->recv_list, vis_packet->sender_orig);
				return(old_info);
			} else {
				/* newer packet is already in hash. */
				return(NULL);
			}
		}
		/* remove old entry */
		hash_remove(vis_hash, old_info);
		free_info(old_info);
	}

	info = kmalloc(sizeof(struct vis_info) + vis_info_len,GFP_KERNEL);
	if (info == NULL)
		return NULL;

	INIT_LIST_HEAD(&info->send_list);
	INIT_LIST_HEAD(&info->recv_list);
	info->first_seen = jiffies;
	memcpy(&info->packet, vis_packet, sizeof(struct vis_packet) + vis_info_len);

	/* initialize and add new packet. */
	*is_new = 1;

	/* repair if entries is longer than packet. */
	if (info->packet.entries * sizeof(struct vis_info_entry) > vis_info_len)
		info->packet.entries = vis_info_len / sizeof(struct vis_info);

	recv_list_add(&info->recv_list, info->packet.sender_orig);

	/* try to add it */
	if (hash_add(vis_hash, info)< 0) {
		/* did not work (for some reason) */
		free_info(info);
		info = NULL;
	}
	return info;
}

/* handle the server sync packet, forward if needed. */
void receive_server_sync_packet(struct vis_packet *vis_packet, int vis_info_len)
{
	struct vis_info *info;
	int is_new;

	spin_lock(&vis_hash_lock);
	info = add_packet(vis_packet, vis_info_len, &is_new);
	if (info == NULL)
		goto end;

	/* only if we are server ourselves and packet is newer than the one in hash.*/
	if (is_vis_server_locked() && is_new) {
		memcpy(info->packet.target_orig, broadcastAddr, ETH_ALEN);
		if (list_empty(&info->send_list)) 
			list_add_tail(&info->send_list, &send_list);
	}

end:
	spin_unlock(&vis_hash_lock);

}

/* handle an incoming client update packet and schedule forward if needed. */
void receive_client_update_packet(struct vis_packet *vis_packet, int vis_info_len)
{
	struct vis_info *info;
	int is_new;
	/* clients shall not broadcast. */
	if (is_bcast(vis_packet->target_orig))
		return;

	spin_lock(&vis_hash_lock);
	info = add_packet(vis_packet, vis_info_len, &is_new);
	if (info == NULL)
		goto end;
	/* note that outdated packets will be dropped at this point. */


	/* send only if we're the target server or ... */
	if (is_vis_server_locked()
		&& is_my_mac(info->packet.target_orig)
		&& is_new) {

		info->packet.vis_type = VIS_TYPE_SERVER_SYNC;	/* upgrade! */
		memcpy(info->packet.target_orig, broadcastAddr, ETH_ALEN);
		if (list_empty(&info->send_list))
			list_add_tail(&info->send_list, &send_list);

	 /* ... we're not the recipient (and thus need to forward). */
	} else if (!is_my_mac(info->packet.target_orig)) {

		if (list_empty(&info->send_list))
			list_add_tail(&info->send_list, &send_list);
	}

end:
	spin_unlock(&vis_hash_lock);
}

/* set the mode of the visualization to client or server */
void vis_set_mode(int mode) 
{
	spin_lock(&vis_hash_lock);

	if (my_vis_info != NULL) 
		my_vis_info->packet.vis_type = mode;

	spin_unlock(&vis_hash_lock);

}

/* is_vis_server(), locked outside */
int is_vis_server_locked(void) 
{
	if (my_vis_info != NULL) 
		if (my_vis_info->packet.vis_type == VIS_TYPE_SERVER_SYNC)
			return 1;

	return 0;
}
/* get the current set mode */
int is_vis_server(void) 
{
	int ret = 0;

	spin_lock(&vis_hash_lock);
	ret = is_vis_server_locked();
	spin_unlock(&vis_hash_lock);

	return ret;
}

/* generates a packet of own vis data,
 * returns 0 on success, -1 if no packet could be generated */

static int generate_vis_packet(void)
{
	struct hash_it_t *hashit = NULL;
	struct orig_node *orig_node;
	struct vis_info *info = (struct vis_info *)my_vis_info;
	struct vis_info_entry *entry, *entry_array;
	struct hna_local_entry *hna_local_entry;
	int best_tq = -1;

	info->first_seen = jiffies;

	spin_lock(&orig_hash_lock);
	memcpy(info->packet.target_orig, broadcastAddr, 6);
	info->packet.ttl = TTL;
	info->packet.seqno++;
	info->packet.entries = 0;

	if (!is_vis_server_locked()) {
		/* find vis-server to receive. */
		while (NULL != (hashit = hash_iterate(orig_hash, hashit))) {
			orig_node = hashit->bucket->data;
			if ((orig_node != NULL) && (orig_node->router != NULL)) {
				if ((orig_node->flags & VIS_SERVER) && orig_node->router->tq_avg > best_tq) {
					best_tq = orig_node->router->tq_avg;
					memcpy(info->packet.target_orig, orig_node->orig,6);
				}
			}
		}
		if (best_tq < 0) {
			spin_unlock(&orig_hash_lock);
			return -1;
		}
	}
	hashit = NULL;

	entry_array = (struct vis_info_entry *)((char *)info + sizeof(struct vis_info));

	while (NULL != (hashit = hash_iterate(orig_hash, hashit))) {
		orig_node = hashit->bucket->data;
		if (orig_node->router != NULL
			&& memcmp(orig_node->router->addr, orig_node->orig, ETH_ALEN) == 0
			&& orig_node->router->tq_avg > 0) {

			/* fill one entry into buffer. */
			entry = &entry_array[info->packet.entries];

			memcpy(entry->dest, orig_node->orig, ETH_ALEN);
			entry->quality = orig_node->router->tq_avg;
			info->packet.entries++;
			/* don't fill more than 1000 bytes */
			if (info->packet.entries + 1 > (1000 - sizeof(struct vis_info)) / sizeof(struct vis_info_entry)) {
				spin_unlock(&orig_hash_lock);
				return 0;
			}
		}
	}

	spin_unlock(&orig_hash_lock);

	hashit = NULL;
	spin_lock(&hna_local_hash_lock);
	while (NULL != (hashit = hash_iterate(hna_local_hash, hashit))) {
		hna_local_entry = hashit->bucket->data;

		entry = &entry_array[info->packet.entries];

		memcpy(entry->dest, hna_local_entry->addr, ETH_ALEN);
		entry->quality = 0; /* 0 means HNA */
		info->packet.entries++;

		/* don't fill more than 1000 bytes */
		if (info->packet.entries + 1 > (1000 - sizeof(struct vis_info)) / sizeof(struct vis_info_entry)) {
			spin_unlock(&hna_local_hash_lock);
			return 0;
		}
	}
	spin_unlock(&hna_local_hash_lock);
	return 0;

}
void purge_vis_packets(void)
{
	struct hash_it_t *hashit = NULL;
	struct vis_info *info;

	spin_lock(&vis_hash_lock);
	while (NULL != (hashit = hash_iterate(vis_hash, hashit))) {
		info = hashit->bucket->data;
		if (info == my_vis_info)	/* never purge own data. */
			continue;
		if (time_after(jiffies, info->first_seen + (VIS_TIMEOUT/1000)*HZ)) {
			hash_remove_bucket(vis_hash, hashit);
			free_info(info);
		}
	}
	spin_unlock(&vis_hash_lock);
}

/* called from timer; send (and maybe generate) vis packet. */
void send_vis_packets(unsigned long arg)
{
	struct vis_info *info, *temp;

	purge_vis_packets();
	spin_lock(&vis_hash_lock);
	if (generate_vis_packet() == 0)
		/* schedule if generation was successful */
		list_add_tail(&my_vis_info->send_list, &send_list);

	list_for_each_entry_safe(info, temp, &send_list, send_list) {
		list_del_init(&info->send_list);
		send_vis_packet(info);
	}
	spin_unlock(&vis_hash_lock);
	start_vis_timer();

}

/* only send one vis packet. called from send_vis_packets() */
void send_vis_packet(struct vis_info *info)
{
	struct hash_it_t *hashit = NULL;
	struct orig_node *orig_node;
	int packet_length;


	if (info->packet.ttl < 2) {
		debug_log(LOG_TYPE_NOTICE, "Error - can't send vis packet: ttl exceeded\n");
		return;
	}

	memcpy(info->packet.sender_orig, mainIfAddr, ETH_ALEN);

	info->packet.ttl--;

	packet_length = sizeof(struct vis_packet) + info->packet.entries * sizeof(struct vis_info_entry);

	if (is_bcast(info->packet.target_orig)) {
		/* broadcast packet */
		spin_lock(&orig_hash_lock);

		/* send to all routers in range. */
		while (NULL != (hashit = hash_iterate(orig_hash, hashit))) {

			orig_node = hashit->bucket->data;

			/* if it's a vis server and reachable, send it. */
			if ((orig_node != NULL) && (orig_node->flags & VIS_SERVER) && (orig_node->batman_if != NULL) && (orig_node->router != NULL)) {

				/* don't send it if we already received the packet from this node. */
				if (recv_list_is_in(&info->recv_list, orig_node->orig))
					continue;


				memcpy(info->packet.target_orig, orig_node->orig, ETH_ALEN);
				send_raw_packet((unsigned char *) &info->packet, packet_length,
						orig_node->batman_if->net_dev->dev_addr, orig_node->router->addr, orig_node->batman_if);
			}
		}
		memcpy(info->packet.target_orig, broadcastAddr, ETH_ALEN);

		spin_unlock(&orig_hash_lock);
	} else {
		/* unicast packet */
		spin_lock(&orig_hash_lock);
		orig_node = ((struct orig_node *) hash_find(orig_hash, info->packet.target_orig));

		if ((orig_node != NULL) && (orig_node->batman_if != NULL) && (orig_node->router != NULL)) {
			send_raw_packet((unsigned char *) &info->packet, packet_length,
					orig_node->batman_if->net_dev->dev_addr, orig_node->router->addr, orig_node->batman_if);
		}
		spin_unlock(&orig_hash_lock);

	}
	info->packet.ttl++; /* restore TTL */
}

/* receive and handle a vis packet */
void receive_vis_packet(struct ethhdr *ethhdr, struct vis_packet *vis_packet, int vis_info_len)
{
	/* ignore own packets */
	if (is_my_mac(vis_packet->vis_orig))
		return;
	if (is_my_mac(vis_packet->sender_orig))
		return;

	switch (vis_packet->vis_type) {
	case VIS_TYPE_SERVER_SYNC:
		receive_server_sync_packet(vis_packet, vis_info_len);
		break;

	case VIS_TYPE_CLIENT_UPDATE:
		receive_client_update_packet(vis_packet, vis_info_len);
		break;

	default:	/* ignore unknown packet */
		break;
	}
}

/* init the vis server. this may only be called when if_list is already initialized
 * (e.g. bat0 is initialized, interfaces have been added) */
int vis_init(void)
{
	vis_hash = hash_new(256, vis_info_cmp, vis_info_choose);
	if (vis_hash == NULL) {
		debug_log(LOG_TYPE_CRIT, "Can't initialize vis_hash\n");
		return(-1);
	}

	my_vis_info = kmalloc(1000, GFP_KERNEL);
	if (my_vis_info == NULL) {
		vis_quit();
		debug_log(LOG_TYPE_CRIT, "Can't initialize vis packet\n");
		return(-1);
	}
	/* prefill the vis info */
	my_vis_info->first_seen = jiffies - atomic_read(&vis_interval);
	INIT_LIST_HEAD(&my_vis_info->recv_list);
	my_vis_info->packet.packet_type = BAT_VIS;
	my_vis_info->packet.vis_type = VIS_TYPE_CLIENT_UPDATE;
	my_vis_info->packet.ttl = TTL;
	my_vis_info->packet.seqno = 0;
	my_vis_info->packet.entries = 0;

	INIT_LIST_HEAD(&send_list);

	memcpy(my_vis_info->packet.vis_orig, mainIfAddr, ETH_ALEN);
	memcpy(my_vis_info->packet.sender_orig, mainIfAddr, ETH_ALEN);

	if (hash_add(vis_hash, my_vis_info) < 0) {
		debug_log(LOG_TYPE_CRIT, "Can't add own vis packet into hash\n");
		free_info(my_vis_info);	/* not in hash, need to remove it manually. */
		vis_quit();
		return(-1);
	}

	start_vis_timer();
	return(0);
}

/* free the info */
void free_info(void *data)
{
	struct vis_info *info = data;
	struct recvlist_node *entry, *tmp;

	list_del_init(&info->send_list);
	list_for_each_entry_safe(entry, tmp, &info->recv_list, list) {
		list_del(&entry->list);
		kfree(entry);
	}
	kfree(info);
}

/* shutdown vis-server */
int vis_quit(void)
{
	spin_lock(&vis_hash_lock);
	del_timer_sync(&vis_timer);
	if (vis_hash != NULL)
		hash_delete(vis_hash, free_info);	/* properly remove, kill timers ... */
	vis_hash = NULL;
	my_vis_info = NULL;
	spin_unlock(&vis_hash_lock);
	return(0);
}

/* schedule own packet for (re)transmission */
void start_vis_timer(void)
{
	init_timer(&vis_timer);

	vis_timer.expires = jiffies + (atomic_read(&vis_interval)/1000) * HZ;
	vis_timer.data = 0;
	vis_timer.function = send_vis_packets;

	add_timer(&vis_timer);
}
