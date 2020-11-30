#ifndef __RTE_MAIO__
#define __RTE_MAIO__

#include <rte_common.h>

#define ETH_MAIO_IFACE_ARG		"iface"
#define ETH_MAIO_QUEUE_COUNT_ARG	"queue_count"

#define ETH_MAIO_DFLT_NUM_DESCS		512

#define NUM_MAX_RINGS	16
#define NUM_RING_TYPES	2
#define RE_SZ	(sizeof(void *))

#define DATA_MTRX_SZ ((ETH_MAIO_DFLT_NUM_DESCS * NUM_MAX_RINGS) * NUM_RING_TYPES * RE_SZ)

struct pmd_internals {
	int if_index;
	char if_name[IFNAMSIZ];
	struct rte_ether_addr eth_addr;
	struct user_matrix *matrix;
};

struct common_ring_info {
	int nr_rx_rings;
	int nr_tx_rings;
	int nr_rx_sz;
	int nr_tx_sz;

	int  meta_len;
	void *rx_rings;
	void *tx_rings;
	void *meta_base;
	void *meta_free;
};

struct meta_ring {
	/* TODO: Add some local stats into each cacheline*/
	/* User writes Kernel Reads */
	unsigned long consumer __rte_cache_aligned;
	/* Kernel writes User Reads */
	unsigned long producer __rte_cache_aligned;
};

struct user_rings {
	struct meta_ring meta[NUM_MAX_RINGS];
	unsigned long long *ring[NUM_MAX_RINGS];

} __rte_cache_aligned;

struct user_matrix {
	struct common_ring_info info;
	struct user_rings rx __rte_cache_aligned;
	struct user_rings tx __rte_cache_aligned;
	/* TODO: MAIO KNI : Just Fix KNI to use z-copy */
	/* Consider Alloc/Free/Completion/Refill rings */

	unsigned long long base[0] __rte_cache_aligned;
};
#endif //__RTE_MAIO__
