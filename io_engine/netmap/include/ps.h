#ifndef _PS_H_
#define _PS_H_

#define MAX_DEVICES	16

#define E_PSIO		FALSE
#define USE_CHUNK_BUF	FALSE

#include <string.h>
#include <stdint.h>
#include <pthread.h>
#include <sys/poll.h>
#include <linux/types.h>

#define __user

#ifndef IFNAMSIZ
#define IFNAMSIZ 16
#endif

#ifndef ETH_ALEN
#define ETH_ALEN 6
#endif

#define ALIGN(x,a)              __ALIGN_MASK(x,(typeof(x))(a)-1)
#define __ALIGN_MASK(x,mask)    (((x)+(mask))&~(mask))

static inline __sum16 ip_fast_csum(const void *iph, unsigned int ihl)
{
	unsigned int sum;

	asm("  movl (%1), %0\n"
	    "  subl $4, %2\n"
	    "  jbe 2f\n"
	    "  addl 4(%1), %0\n"
	    "  adcl 8(%1), %0\n"
	    "  adcl 12(%1), %0\n"
	    "1: adcl 16(%1), %0\n"
	    "  lea 4(%1), %1\n"
	    "  decl %2\n"
	    "  jne      1b\n"
	    "  adcl $0, %0\n"
	    "  movl %0, %2\n"
	    "  shrl $16, %0\n"
	    "  addw %w2, %w0\n"
	    "  adcl $0, %0\n"
	    "  notl %0\n"
	    "2:"
	    /* Since the input registers which are loaded with iph and ih
	       are modified, we must also specify them as outputs, or gcc
	       will assume they contain their original values. */
	    : "=r" (sum), "=r" (iph), "=r" (ihl)
	    : "1" (iph), "2" (ihl)
	       : "memory");
	return (__sum16)sum;
}

struct ps_device {
	char name[IFNAMSIZ];
	char dev_addr[ETH_ALEN];
	uint32_t ip_addr;	/* network order */

	/* NOTE: this is different from kernel's internal index */
	int ifindex;

	/* This is kernel's ifindex. */
	int kifindex;

	int num_rx_queues;
	int num_tx_queues;
};

struct ps_queue {
	int ifindex;
	int qidx;
};

#define MAX_PACKET_SIZE	2048
#define MAX_CHUNK_SIZE	1024

struct ps_pkt_info {
	uint32_t offset;
	uint16_t len;
};

struct ps_chunk {
	/* number of packets to send/recv */
	int cnt;
	int recv_blocking;

	/* 
	   for RX: output (where did these packets come from?)
	   for TX: input (which interface do you want to xmit?)
	 */
	struct ps_queue queue;

	struct ps_pkt_info __user *info;
	char __user *buf;
};

struct ps_packet {
	int ifindex;
	int len;
	char __user *buf;
};

static inline void prefetcht0(void *p)
{
	asm volatile("prefetcht0 (%0)\n\t"
			: 
			: "r" (p)
		    );
}

static inline void prefetchnta(void *p)
{
	asm volatile("prefetchnta (%0)\n\t"
			: 
			: "r" (p)
		    );
}

static inline void memcpy_aligned(void *to, const void *from, size_t len)
{
	if (len <= 64) {
		memcpy(to, from, 64);
	} else if (len <= 128) {
		memcpy(to, from, 64);
		memcpy((uint8_t *)to + 64, (uint8_t *)from + 64, 64);
	} else {
		size_t offset;

		for (offset = 0; offset < len; offset += 64)
			memcpy((uint8_t *)to + offset, 
					(uint8_t *)from + offset, 
					64);
	}
}

struct ps_handle {
	int fd;

	int queue_count;
	struct ps_queue queues[MAX_DEVICES];

	/* Current Rx device for round-robin device polling */
	int rx_device;
};

int ps_list_devices(struct ps_device *devices);
int ps_init_handle(struct ps_handle *handle);
void ps_close_handle(struct ps_handle *handle);
int ps_alloc_qidx(struct ps_device *device, int cpu);
void ps_free_qidx(struct ps_device *device, int cpu, int qidx);
int ps_attach_rx_device(struct ps_handle *handle, struct ps_queue *queue);
int ps_detach_rx_device(struct ps_handle *handle, struct ps_queue *queue);
int ps_alloc_chunk(struct ps_handle *handle, struct ps_chunk *chunk);
void ps_free_chunk(struct ps_chunk *chunk);
int ps_recv_chunk(struct ps_handle *handle, struct ps_chunk *chunk);
int ps_send_chunk(struct ps_handle *handle, struct ps_chunk *chunk);
int ps_slowpath_packet(struct ps_handle *handle, struct ps_packet *packet);

#endif	/* _PS_H_ */
