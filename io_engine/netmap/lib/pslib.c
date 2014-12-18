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

#define TRACE_ERROR(msg...)	fprintf(stderr, msg)
#define TRACE_INFO(msg...)	fprintf(stderr, msg)

#define NETMAP_MAX_QUEUES_PER_DEVICE	64

struct netmap_priv_device {
	char name[IFNAMSIZ];
	pthread_spinlock_t host_lock;
	struct nm_desc *host_nmd;
	struct nm_desc *nmd;

	struct ps_device *dev;

	pthread_spinlock_t queue_lock;
	int queue_count;
	int queue_avail[NETMAP_MAX_QUEUES_PER_DEVICE];
};

struct netmap_shmem_control {
	char *nic_ifnames;
	int ndevs_count;
	struct netmap_priv_device ndevs[MAX_DEVICES];
};

static struct netmap_shmem_control *ctrl;

static int init_ndev(int ifindex, char *name)
{
	int i;
	char ifn[IFNAMSIZ];
	struct netmap_priv_device *ndev = &ctrl->ndevs[ifindex];

	strcpy(ndev->name, name);

	pthread_spin_init(&ndev->host_lock, PTHREAD_PROCESS_SHARED);
	snprintf(ifn, sizeof(ifn), "netmap:%s^", name);
	ndev->host_nmd = nm_open(ifn, NULL, 0, NULL);
	if (!ndev->host_nmd) {
		TRACE_ERROR("%s: failed to open host netmap for %s\n",
			    __func__, name);
		assert(0);
		return -1;
	}

	snprintf(ifn, sizeof(ifn), "netmap:%s", name);
	ndev->nmd = nm_open(ifn, NULL, NM_OPEN_NO_MMAP, ndev->host_nmd);
	if (!ndev->nmd) {
		TRACE_ERROR("%s: failed to open NIC netmap for %s\n",
			    __func__, name);
		return -1;
	}

	pthread_spin_init(&ndev->queue_lock, PTHREAD_PROCESS_SHARED);
	ndev->queue_count = ndev->nmd->req.nr_rx_rings;
	if (ndev->nmd->req.nr_tx_rings < ndev->queue_count)
		ndev->queue_count = ndev->nmd->req.nr_tx_rings;
	if (NETMAP_MAX_QUEUES_PER_DEVICE < ndev->queue_count)
		ndev->queue_count = NETMAP_MAX_QUEUES_PER_DEVICE;

	for (i = 0; i < ndev->queue_count; i++)
		ndev->queue_avail[i] = 1;

	return 0;
}

int ps_init(void)
{
	int i, j, ret;
	char ifname[IFNAMSIZ];
	char env[] = "MTCP_NETMAP_NIC_NAMES";

	ctrl = (struct netmap_shmem_control *)mmap(NULL, sizeof(*ctrl), 
		PROT_READ|PROT_WRITE, MAP_SHARED|MAP_ANONYMOUS, -1, 0);
	if (!ctrl) {
		TRACE_ERROR("%s: failed allocate control shared memory\n",
			    __func__);
		assert(0);
	}
	memset(ctrl, 0, sizeof(*ctrl));

	ctrl->nic_ifnames = getenv(env);
	if (!ctrl->nic_ifnames) {
		TRACE_ERROR("%s: failed to get environment variable %s\n",
			    __func__, env);
		assert(0);
	}

	i = 0;
	j = 0;
	memset(ifname, 0, sizeof(ifname));
	while (ctrl->nic_ifnames[i] && (ctrl->ndevs_count < MAX_DEVICES)) {
		if (ctrl->nic_ifnames[i] != ' ') {
			if (j < (IFNAMSIZ - 8)) {
				ifname[j] = ctrl->nic_ifnames[i];
				j++;
			}
			i++;
			continue;
		}

		if (j) {
			ret = init_ndev(ctrl->ndevs_count, ifname);
			if (ret) {
				TRACE_ERROR("%s: failed to init netmap NIC %s "
					"(error %d)\n", __func__, ifname, ret);
				assert(0);
			}
			ctrl->ndevs_count++;
		}

		memset(ifname, 0, sizeof(ifname));
		j = 0;
		i++;
	}
	if (j && (ctrl->ndevs_count < MAX_DEVICES)) {
		ret = init_ndev(ctrl->ndevs_count, ifname);
		if (ret) {
			TRACE_ERROR("%s: failed to init netmap NIC %s "
				    "(error %d)\n", __func__, ifname, ret);
			assert(0);
		}
		ctrl->ndevs_count++;
	}

	return 0;
}

int ps_list_devices(struct ps_device *devices)
{
	int ifindex;
	struct ps_device *dev;
	struct netmap_priv_device *ndev;

	for (ifindex = 0; ifindex < ctrl->ndevs_count; ifindex++) {
		ndev = &ctrl->ndevs[ifindex];
		dev = &devices[ifindex];
		strcpy(dev->name, ndev->name);
		dev->ifindex = ifindex;
		dev->kifindex = ifindex;
		dev->num_rx_queues = dev->num_tx_queues = ndev->queue_count;
	}

	return ctrl->ndevs_count;
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
	struct netmap_priv_device *ndev = &ctrl->ndevs[device->ifindex];

	pthread_spin_lock(&ndev->queue_lock);

	for (i = 0; i < ndev->queue_count; i++) {
		if (ndev->queue_avail[i]) {
			ret = i;
			ndev->queue_avail[i] = 0;
			break;
		}
	}

	pthread_spin_unlock(&ndev->queue_lock);

	if (ret == -1) {
		TRACE_ERROR("%s: failed for device %s and cpu%d\n",
			    __func__, device->name, cpu);
		assert(0);
	}

	return ret;
}

void ps_free_qidx(struct ps_device *device, int cpu, int qidx)
{
	struct netmap_priv_device *ndev = &ctrl->ndevs[device->ifindex];

	if ((0 <= qidx) && (qidx < NETMAP_MAX_QUEUES_PER_DEVICE)) {
		pthread_spin_lock(&ndev->queue_lock);

		ndev->queue_avail[qidx] = 1;

		pthread_spin_unlock(&ndev->queue_lock);
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
		TRACE_ERROR("%s: failed to alloc chunk info\n", __func__);
		assert(0);
		return -1;
	}

	chunk->buf = malloc(MAX_PACKET_SIZE * MAX_CHUNK_SIZE);
	if (!chunk->buf) {
		TRACE_ERROR("%s: failed to alloc chunk buffer\n", __func__);
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

/* Send the given chunk to the modified driver. */
int ps_send_chunk(struct ps_handle *handle, struct ps_chunk *chunk)
{
	u_int cur;
	int i, send = 0, ifindex = chunk->queue.ifindex;
	struct ps_queue *queue;
	struct netmap_priv_device *ndev;
	struct netmap_ring *txring;

	/* Sanity check */
	if ((ifindex < 0) || (MAX_DEVICES <= ifindex)) {
		TRACE_ERROR("%s: invalid ifindex=%d\n", __func__, ifindex);
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
		TRACE_ERROR("%s: tx queue not found for ifindex=%d\n",
			__func__, ifindex);
		assert(0);
	}

	/* Find netmap private device and netmap ring */
	ndev = &ctrl->ndevs[ifindex];
	txring = NETMAP_TXRING(ndev->nmd->nifp, queue->qidx);

	/* Find current netmap slot in NIC Tx ring */
	cur = txring->cur;

	/* Copy over the packets to netmap ring */
	while (nm_ring_space(txring) && (send < chunk->cnt)) {
		struct netmap_slot *slot = &txring->slot[cur];

		/* Update current netmap slot */
		nm_pkt_copy(chunk->buf + chunk->info[send].offset,
			    NETMAP_BUF(txring, slot->buf_idx),
			    chunk->info[send].len);
		slot->flags = 0;
		slot->len = chunk->info[send].len;
		send++;

		/* Point to next netmap slot */
		cur = nm_ring_next(txring, cur);
		txring->head = txring->cur = cur;
	}

	/* Notify kernel about packets */
	if (send)
		ioctl(ndev->nmd->fd, NIOCTXSYNC, NULL);

	return send;
}

int ps_slowpath_packet(struct ps_handle *handle, struct ps_packet *packet)
{
	u_int cur;
	int ret = 1, ifindex = packet->ifindex;
	struct netmap_priv_device *ndev;
	struct netmap_slot *slot;
	struct netmap_ring *txring;

	if ((ifindex < 0) || (MAX_DEVICES <= ifindex)) {
		TRACE_ERROR("%s: invalid ifindex=%d\n", __func__, ifindex);
		assert(0);
	}

	/* Find netmap private device and netmap ring */
	ndev = &ctrl->ndevs[ifindex];
	txring = NETMAP_TXRING(ndev->host_nmd->nifp,
					ndev->host_nmd->last_tx_ring);

	/* Lock host ring of netmap private device */
	pthread_spin_lock(&ndev->host_lock);

	/* Recheck space availablity in netmap ring */
	if (!nm_ring_space(txring)) {
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
	ret = 1;

	/* Update netmap ring head */
	txring->head = txring->cur = nm_ring_next(txring, cur);

done:
	/* Unlock host ring of netmap private device */
	pthread_spin_unlock(&ndev->host_lock);

	/* Notify kernel about packets */
	if (ret)
		ioctl(ndev->host_nmd->fd, NIOCTXSYNC, NULL);

	return ret;
}

int ps_recv_chunk(struct ps_handle *handle, struct ps_chunk *chunk)
{
	u_int cur, host_cur;
	int host_send;
	int i, recv, count;
	struct pollfd pfds[MAX_DEVICES*2];
	struct ps_queue *queue;
	struct netmap_priv_device *ndev;
	struct netmap_ring *rxring;
	struct netmap_ring *txring;
	struct netmap_ring *host_rxring;

	/* Setup poll structure */
	for (i = 0; i < handle->queue_count*2; i+=2) {
		ndev = &ctrl->ndevs[handle->queues[i].ifindex];
		pfds[i].fd = ndev->nmd->fd;
		pfds[i].events = POLLIN;
		pfds[i].revents = 0;
		pfds[i+1].fd = ndev->host_nmd->fd;
		pfds[i+1].events = POLLIN;
		pfds[i+1].revents = 0;
	}

	/* Wait for incoming packets with No timeout */
	poll(pfds, handle->queue_count*2, handle->queue_count*500);

	/* Check each device for Rx packets starting from handle->rx_device */
	recv = 0;
	i = handle->rx_device;
	count = handle->queue_count;
	while (count && !recv) {
		queue = &handle->queues[i];
		ndev = &ctrl->ndevs[queue->ifindex];

		/* Check for poll error */
		if (pfds[2*i].revents & POLLERR) {
			/* Find out netmap Rx ring */
			rxring = NETMAP_RXRING(ndev->nmd->nifp, queue->qidx);
			TRACE_ERROR("%s: poll error for ifindex=%d empty=%d\n",
				    __func__, queue->ifindex, nm_ring_empty(rxring));
		}

		/* Check for poll in */
		if (pfds[2*i].revents & POLLIN) {
			/* Find out netmap NIC Rx ring */
			rxring = NETMAP_RXRING(ndev->nmd->nifp, queue->qidx);
			cur = rxring->cur;

			/* Copy over NIC Rx packets to chunk */
			while (!nm_ring_empty(rxring) &&
				(recv < chunk->cnt)) {
				struct netmap_slot *slot = &rxring->slot[cur];

				/* Forward single Rx packet to mTCP */
				if (recv) {
					chunk->info[recv].offset =
						chunk->info[recv-1].offset +
						chunk->info[recv-1].len;
				} else {
					chunk->info[recv].offset = 0;
				}
				chunk->info[recv].len = slot->len;
				nm_pkt_copy(NETMAP_BUF(rxring, slot->buf_idx),
					chunk->buf + chunk->info[recv].offset,
					chunk->info[recv].len);
				recv++;

				/* Point to next netmap slot */
				cur = nm_ring_next(rxring, cur);
				rxring->head = rxring->cur = cur;
			}
		}

		/* Check for poll error */
		if (pfds[2*i+1].revents & POLLERR) {
			/* Find out netmap Rx ring */
			rxring = NETMAP_RXRING(ndev->host_nmd->nifp,
					       ndev->host_nmd->last_rx_ring);
			TRACE_ERROR("%s: poll error for ifindex=%d\n",
				    __func__, queue->ifindex);
		}

		/* Check for poll in */
		if (pfds[2*i+1].revents & POLLIN) {
			/* Find out netmap host Rx ring */
			host_rxring = NETMAP_RXRING(ndev->host_nmd->nifp,
						ndev->host_nmd->last_rx_ring);
			host_cur = host_rxring->cur;

			/* Find out netmap NIC Tx ring */
			txring = NETMAP_TXRING(ndev->nmd->nifp, queue->qidx);
			cur = txring->cur;

			/* Lock host ring of netmap private device */
			pthread_spin_lock(&ndev->host_lock);

			/* Copy over host packets to Tx ring */
			host_send = 0;
			while (!nm_ring_empty(host_rxring) &&
				nm_ring_space(txring) &&
				(host_send < 4)) {
				struct netmap_slot *host_slot =
						&host_rxring->slot[host_cur];
				struct netmap_slot *slot = &txring->slot[cur];
				uint32_t buf_idx = host_slot->buf_idx;

				/* Zero-copy */
				host_slot->buf_idx = slot->buf_idx;
				slot->buf_idx = buf_idx;
				host_slot->flags |= NS_BUF_CHANGED;
				slot->flags |= NS_BUF_CHANGED;
				slot->len = host_slot->len;
				host_send++;

				/* Point to next netmap slot in host Rx ring */
				host_cur = nm_ring_next(host_rxring, host_cur);
				host_rxring->head = host_rxring->cur = host_cur;

				/* Point to next netmap slot in Tx Ring */
				cur = nm_ring_next(txring, cur);
				txring->head = txring->cur = cur;
			}

			/* Unlock host ring of netmap private device */
			pthread_spin_unlock(&ndev->host_lock);
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

