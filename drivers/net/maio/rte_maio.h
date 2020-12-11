#ifndef __RTE_MAIO__
#define __RTE_MAIO__

#include <rte_common.h>

#define PAGES_0_PROC_NAME		"/proc/maio/pages_0"
#define MTRX_PROC_NAME			"/proc/maio/mtrx"
#define MAP_PROC_NAME			"/proc/maio/map"
#define ENABLE_PROC_NAME		"/proc/maio/enable"
#define ETH_MAIO_IFACE_ARG		"iface"
#define ETH_MAIO_QUEUE_COUNT_ARG	"queue_count"

#define ETH_MAIO_FRAME_SIZE		2048
#define ETH_MAIO_MBUF_STRIDE		0x800 	// TODO: same as frame size - need to check if redundant
#define ETH_MAIO_MBUF_OVERHEAD		0	/*TODO: Velo overhed is set here... */
#define ETH_MAIO_DATA_HEADROOM 		(ETH_MAIO_MBUF_OVERHEAD + RTE_PKTMBUF_HEADROOM)
#define ETH_MAIO_DFLT_NUM_DESCS		512

#define NUM_MAX_RINGS	16
#define NUM_RING_TYPES	2
#define RE_SZ	(sizeof(void *))

#define DATA_MTRX_SZ ((ETH_MAIO_DFLT_NUM_DESCS * NUM_MAX_RINGS) * NUM_RING_TYPES * RE_SZ)

#define max(a, b) (a > b ? (uint64_t)a : (uint64_t)b)
#define min(a, b) (a < b ? (uint64_t)a : (uint64_t)b)

struct meta_pages_0 {
	uint16_t nr_pages;
	uint16_t stride;
	uint16_t headroom;
	uint16_t flags;
	void *bufs[0];
};

struct in_params {
	char if_name[IFNAMSIZ];
	int q_cnt;
};

struct pmd_internals {
	struct rte_mempool *mb_pool;
	int if_index;
	int q_cnt;
	char if_name[IFNAMSIZ];
	struct rte_ether_addr eth_addr;
	struct user_matrix *matrix;
};

struct common_ring_info {
	uint32_t nr_rx_rings;
	uint32_t nr_tx_rings;
	uint32_t nr_rx_sz;
	uint32_t nr_tx_sz;

	/* MUST be the same as set in user_rings */
	/*
		The motivation is to have one set place to share info
		and another to  allow both user and kernel to change
		w/o breaking the other
	*/
	unsigned long long *rx_rings[NUM_MAX_RINGS];
	unsigned long long *tx_rings[NUM_MAX_RINGS];
};

# if 0
struct meta_ring {
	/* TODO: Add some local stats into each cacheline*/
	/* User writes Kernel Reads */
	unsigned long consumer __rte_cache_aligned;
	/* Kernel writes User Reads */
	unsigned long producer __rte_cache_aligned;
};
#endif
// The preferred way:
// 	Both consumer and producer have only their local counter.
//	entry is available for consumption if full/flag set for large entries, free otherwise.
//	in our case each entry is just a void *.
//	Namely, rings MUST be zeroed-out on init.
struct meta_ring {
	unsigned long consumer;
	// For SMP- a per core consumer.
	//unsigned long consumer __rte_cache_aligned;
};

struct user_rings {
	struct meta_ring meta[NUM_MAX_RINGS];
	unsigned long long *ring[NUM_MAX_RINGS];

} __rte_cache_aligned;

struct user_matrix {
	struct common_ring_info info;
#if 0
	//SMP_MULTIPLE_POLLERS
	struct user_rings rx __rte_cache_aligned;
	struct user_rings tx __rte_cache_aligned;
	/* TODO: MAIO KNI : Just Fix KNI to use z-copy */
	/* Consider Alloc/Free/Completion/Refill rings */
#endif
	//Best for single core user I/O
	struct user_rings rx;
	struct user_rings tx;

	unsigned long long base[0] __rte_cache_aligned;
};
#endif //__RTE_MAIO__
