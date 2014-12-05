#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <fcntl.h>
#include <unistd.h>
#include <sched.h>
#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <pthread.h>

#include <sys/mman.h>
#include <sys/ioctl.h>

#define NETMAP_WITH_LIBS
#include <net/netmap_user.h>

#include "../include/ps.h"

#define NETMAP_MAX_QUEUES_PER_DEVICE	64

struct netmap_priv_device {
	struct nm_desc *nmd;

	struct ps_device *dev;

	pthread_mutex_t queue_mutex;
	int queue_count;
	int queue_avail[NETMAP_MAX_QUEUES_PER_DEVICE];
};

static char *nic_ifnames;
static pthread_mutex_t host_mutex;
static struct nm_desc *host_nmd;
static int ndevs_count;
static struct netmap_priv_device ndevs[MAX_DEVICES];

static int init_ndev(struct ps_device *devices, int ifindex, char *name)
{
	int i;
	char ifn[IFNAMSIZ];
	struct ps_device *dev = &devices[ifindex];
	struct netmap_priv_device *ndev = &ndevs[ifindex];

	snprintf(ifn, sizeof(ifn), "netmap:%s", name);
	ndev->nmd = nm_open(ifn, NULL, NM_OPEN_NO_MMAP, host_nmd);
	if (!ndev->nmd) {
		printf("%s: cannot open %s\n", __func__, ifn);
		return -1;
	}

	strcpy(dev->name, name);
	dev->ifindex = ifindex;
	dev->kifindex = ifindex;
	dev->num_rx_queues = ndev->nmd->req.nr_rx_rings;
	dev->num_tx_queues = ndev->nmd->req.nr_rx_rings;
	ndev->dev = dev;

	pthread_mutex_init(&ndev->queue_mutex, NULL);
	ndev->queue_count = dev->num_rx_queues;
	if (dev->num_tx_queues < ndev->queue_count)
		ndev->queue_count = dev->num_tx_queues;
	if (NETMAP_MAX_QUEUES_PER_DEVICE < ndev->queue_count)
		ndev->queue_count = NETMAP_MAX_QUEUES_PER_DEVICE;

	for (i = 0; i < ndev->queue_count; i++)
		ndev->queue_avail[i] = 1;

	return 0;
}

int ps_list_devices(struct ps_device *devices)
{
	int i, j, ret;
	char ifname[IFNAMSIZ];
	char env[] = "MTCP_NETMAP_NIC_NAMES";

	nic_ifnames = getenv(env);
	if (!nic_ifnames) {
		printf("%s: failed to get environment variable %s\n",
			__func__, env);
		assert(0);
		return -1;
	}

	pthread_mutex_init(&host_mutex, NULL);

	memset(ifname, 0, sizeof(ifname));
	host_nmd = nm_open(ifname, NULL, 0, NULL);
	if (!host_nmd) {
		printf("%s: failed to open host netmap\n", __func__);
		assert(0);
		return -1;
	}

	ndevs_count = 0;
	memset(ndevs, 0, sizeof(ndevs));

	i = 0;
	j = 0;
	while (nic_ifnames[i] && (ndevs_count < MAX_DEVICES)) {
		if (nic_ifnames[i] != ' ') {
			if (j < (IFNAMSIZ - 8)) {
				ifname[j] = nic_ifnames[i];
				j++;
			}
			i++;
			continue;
		}

		if (j) {
			ret = init_ndev(devices, ndevs_count, ifname);
			if (ret) {
				printf("%s: failed to init NIC %s "
					"in netmap mode\n", __func__, ifname);
				assert(0);
				return ret;
			}
			ndevs_count++;
		}

		memset(ifname, 0, sizeof(ifname));
		j = 0;
		i++;
	}
	if (j && (ndevs_count < MAX_DEVICES)) {
		ret = init_ndev(devices, ndevs_count, ifname);
		if (ret) {
			printf("%s: failed to init NIC %s in netmap mode\n",
				__func__, ifname);
			assert(0);
			return ret;
		}
		ndevs_count++;
	}

	return ndevs_count;
}

int ps_init_handle(struct ps_handle *handle)
{
	int i;

	memset(handle, 0, sizeof(*handle));

	handle->fd = -1;

	handle->queue_count = 0;
	for (i = 0; i < MAX_DEVICES; i++) {
		handle->queues[i].ifindex = -1;
		handle->queues[i].qidx = -1;
	}

	handle->rx_device = 0;

	return 0;
}

void ps_close_handle(struct ps_handle *handle)
{
	/* Nothing to do here. */
}

int ps_alloc_qidx(struct ps_device *device, int cpu)
{
	int i, ret = -1;
	struct netmap_priv_device *ndev = &ndevs[device->ifindex];

	pthread_mutex_lock(&ndev->queue_mutex);

	for (i = 0; i < ndev->queue_count; i++) {
		if (ndev->queue_avail[i]) {
			ret = i;
			ndev->queue_avail[i] = 0;
			break;
		}
	}

	pthread_mutex_unlock(&ndev->queue_mutex);

	if (ret == -1) {
		printf("%s: failed for device %s and cpu%d\n",
			__func__, device->name, cpu);
		assert(0);
	}

	return ret;
}

void ps_free_qidx(struct ps_device *device, int cpu, int qidx)
{
	struct netmap_priv_device *ndev = &ndevs[device->ifindex];

	if ((0 <= qidx) && (qidx < NETMAP_MAX_QUEUES_PER_DEVICE)) {
		pthread_mutex_lock(&ndev->queue_mutex);

		ndev->queue_avail[qidx] = 1;

		pthread_mutex_unlock(&ndev->queue_mutex);
	}
}

int ps_attach_rx_device(struct ps_handle *handle, struct ps_queue *queue)
{
	/* Nothing to do here. */
	return 0;
}

int ps_detach_rx_device(struct ps_handle *handle, struct ps_queue *queue)
{
	/* Nothing to do here. */
	return 0;
}

int ps_alloc_chunk(struct ps_handle *handle, struct ps_chunk *chunk)
{
	memset(chunk, 0, sizeof(*chunk));

	chunk->info = (struct ps_pkt_info *)malloc(
			sizeof(struct ps_pkt_info) * MAX_CHUNK_SIZE);
	if (!chunk->info) {
		printf("%s: failed to alloc chunk info\n", __func__);
		assert(0);
		return -1;
	}

	chunk->buf = malloc(MAX_PACKET_SIZE * MAX_CHUNK_SIZE);
	if (!chunk->buf) {
		printf("%s: failed to alloc chunk buffer\n", __func__);
		assert(0);
		return -1;
	}
	
	return 0;
}

void ps_free_chunk(struct ps_chunk *chunk)
{
	free(chunk->info);
	free(chunk->buf);

	chunk->info = NULL;
	chunk->buf = NULL;
}

int ps_recv_chunk(struct ps_handle *handle, struct ps_chunk *chunk)
{
	u_int cur;
	int i, recv, count;
	struct pollfd pfds[MAX_DEVICES];
	struct ps_queue *queue;
	struct netmap_priv_device *ndev;
	struct netmap_ring *rxring;

	/* Setup poll structure */
	for (i = 0; i < handle->queue_count; i++) {
		ndev = &ndevs[handle->queues[i].ifindex];
		pfds[i].fd = ndev->nmd->fd;
		pfds[i].events = POLLIN;
		pfds[i].revents = 0;
	}

	/* Wait for incoming packets with 500ms timeout */
	poll(pfds, handle->queue_count, 500);

	/* Check each device for Rx packets starting from handle->rx_device */
	recv = 0;
	i = handle->rx_device;
	count = handle->queue_count;
	while (count && !recv) {
		queue = &handle->queues[i];
		ndev = &ndevs[queue->ifindex];

		/* Check poll return events */
		if (pfds[i].revents & POLLERR) {
			printf("%s: poll error for ifindex=%d\n",
				__func__, queue->ifindex);
		} else if (pfds[i].revents & POLLIN) {
			/* Find out netmap Rx ring */
			rxring = NETMAP_RXRING(ndev->nmd->nifp, queue->qidx);
			cur = rxring->cur;

			/* Copy over Rx packets to chunk */
			while (!nm_ring_empty(rxring) &&
				(recv < chunk->cnt)) {
				struct netmap_slot *slot = &rxring->slot[cur];

				/* Update offset and len in chunk */
				if (recv) {
					chunk->info[recv].offset =
						chunk->info[recv-1].offset +
						chunk->info[recv-1].len;
				} else {
					chunk->info[recv].offset = 0;
				}
				chunk->info[recv].len = slot->len;

				/* Copy single Rx packet to chunk */
				nm_pkt_copy(NETMAP_BUF(rxring, slot->buf_idx),
					chunk->buf + chunk->info[recv].offset,
					chunk->info[recv].len);

				/* Point to next netmap slot */
				cur = nm_ring_next(rxring, cur);
				recv++;
			}

			/* Update netmap ring head */
			rxring->head = rxring->cur = cur;
		}

		/* Point to next Rx device */
		i++;
		if (i == handle->queue_count) {
			i = 0;
		}
		count--;
	}
	handle->rx_device = i;

	return recv;
}

/* Send the given chunk to the modified driver. */
int ps_send_chunk(struct ps_handle *handle, struct ps_chunk *chunk)
{
	u_int cur;
	int i, ifindex = chunk->queue.ifindex;
	struct ps_queue *queue;
	struct netmap_priv_device *ndev;
	struct netmap_ring *txring;

	/* Sanity check */
	if ((ifindex < 0) || (MAX_DEVICES <= ifindex)) {
		printf("%s: invalid ifindex=%d\n", __func__, ifindex);
		assert(0);
	}

	/* Find appropriate ps_queue of given ifindex */
	queue = NULL;
	for (i = 0; i < handle->queue_count; i++) {
		if (handle->queues[i].ifindex == ifindex) {
			queue = &handle->queues[i];
		}
	}
	if (!queue) {
		printf("%s: tx queue not found for ifindex=%d\n",
			__func__, ifindex);
		assert(0);
	}

	/* Find netmap private device and netmap ring */
	ndev = &ndevs[ifindex];
	txring = NETMAP_TXRING(ndev->nmd->nifp, queue->qidx);

	/* Find current netmap slot */
	cur = txring->cur;

	/* Copy over the packets to netmap ring */
	i = 0;
	while (nm_ring_space(txring) && (i < chunk->cnt)) {
		struct netmap_slot *slot = &txring->slot[cur];

		/* Update current netmap slot */
		nm_pkt_copy(chunk->buf + chunk->info[i].offset,
			    NETMAP_BUF(txring, slot->buf_idx),
			    chunk->info[i].len);
		slot->flags = 0;
		slot->len = chunk->info[i].len;

		/* Point to next netmap slot */
		cur = nm_ring_next(txring, cur);
		i++;
	}

	/* Update netmap ring head */
	txring->head = txring->cur = cur;

	if (i) {
		/* Notify netmap kernel module about available packets */
		ioctl(ndev->nmd->fd, NIOCTXSYNC, NULL);
	}

	return i;
}

int ps_slowpath_packet(struct ps_handle *handle, struct ps_packet *packet)
{
	u_int cur;
	int ret = 1, ifindex = packet->ifindex;
	struct netmap_slot *slot;
	struct netmap_ring *txring;

	if ((ifindex < 0) || (MAX_DEVICES <= ifindex)) {
		printf("%s: invalid ifindex=%d\n", __func__, ifindex);
		assert(0);
	}

	/* Find netmap netmap ring */
	txring = NETMAP_TXRING(host_nmd->nifp, 0);

	/* Lock host netmap */
	pthread_mutex_lock(&host_mutex);

	/* Recheck space availablity in netmap ring */
	if (!nm_ring_space(txring)) {
		printf("%s: dropping packet\n", __func__);
		ret = 0;
		goto done;
	}

	/* Find current netmap slot */
	cur = txring->cur;
	slot = &txring->slot[cur];

	/* Update current netmap slot */
	nm_pkt_copy(packet->buf,
		    NETMAP_BUF(txring, slot->buf_idx),
		    packet->len);
	slot->flags = 0;
	slot->len = packet->len;

	/* Update netmap ring head */
	txring->head = txring->cur = nm_ring_next(txring, cur);

	/* Notify netmap kernel module about available packets */
	ioctl(host_nmd->fd, NIOCTXSYNC, NULL);

done:
	/* Lock host netmap */
	pthread_mutex_unlock(&host_mutex);

	return ret;
}
