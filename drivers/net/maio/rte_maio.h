#ifndef __RTE_MAIO__
#define __RTE_MAIO__

#include <rte_common.h>

#define MAIO_POISON (0xFEA20FDAU)

#define PAGES_0_PROC_NAME		"/proc/maio/pages_0"
#define MTRX_PROC_NAME			"/proc/maio/mtrx"
#define TX_PROC_NAME			"/proc/maio/tx"
#define MAP_PROC_NAME			"/proc/maio/map"
#define ENABLE_PROC_NAME		"/proc/maio/enable"
#define STOP_PROC_NAME                  "/proc/maio/stop"

#define ETH_MAIO_IFACE_ARG		"iface"
#define ETH_MAIO_QUEUE_COUNT_ARG	"queue_count"

#define ALLIGNED_MBUF_OFFSET 		(sizeof(struct rte_mempool_objhdr))
#define ETH_MAIO_FRAME_SIZE		4096
#define ETH_MAIO_MBUF_STRIDE		0x1000 	// TODO: same as frame size - need to check if redundant
#define ETH_MAIO_STRIDE_MASK		(~(ETH_MAIO_MBUF_STRIDE -1))
#define ETH_MAIO_DFLT_NUM_DESCS		1024
#define ETH_MAIO_DFLT_DESC_MASK		(ETH_MAIO_DFLT_NUM_DESCS - 1)
#define ETH_MAIO_NUM_INIT_BUFFS		(ETH_MAIO_DFLT_NUM_DESCS << 6)	//64K


//#define ETH_MAIO_MBUF_OVERHEAD		0	/*TODO: Velo overhed is set here... */
//#define ETH_MAIO_DATA_HEADROOM 		(ETH_MAIO_MBUF_OVERHEAD + RTE_PKTMBUF_HEADROOM)

#define NUM_MAX_RINGS	16
#define NUM_RING_TYPES	2
#define RE_SZ	(sizeof(void *))

#define DATA_MTRX_SZ ((ETH_MAIO_DFLT_NUM_DESCS * NUM_MAX_RINGS) * NUM_RING_TYPES * RE_SZ)

#define max(a, b) (a > b ? (uint64_t)a : (uint64_t)b)
#define min(a, b) (a < b ? (uint64_t)a : (uint64_t)b)

#define HP_SHIFT	21
#define HP_SIZE		(1<<HP_SHIFT)
#define HP_MASK		(HP_SIZE-1)
#define ALIGN_HP(x)    	(((x) + (HP_MASK)) & ~(HP_MASK))
#define DIV_ROUND_UP_HP(n) (((n) + HP_MASK) >> HP_SHIFT)
/***************************** SYNC WITH KERNEL DEFINITIONS *******************/
struct io_md {
	uint32_t len;
	uint32_t poison;
};

struct meta_pages_0 {
	uint16_t nr_pages;
	uint16_t stride;
	uint16_t headroom;
	uint16_t flags;
	void *bufs[0];
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

/******************************************************************************/

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

struct user_ring {
	unsigned long consumer;
	unsigned long long *ring;

};// __rte_cache_aligned;

struct tx_user_ring {
	unsigned long consumer;
	unsigned long long *ring;
	int fd;
	int idx;

};// __rte_cache_aligned;

struct user_matrix {
	/* MUST BE FIRST - used by the Kernel */
	struct common_ring_info info;
#if 0
	//SMP_MULTIPLE_POLLERS
	struct user_rings rx ;
	struct user_rings tx __rte_cache_aligned;
	/* TODO: MAIO KNI : Just Fix KNI to use z-copy */
	/* Consider Alloc/Free/Completion/Refill rings */
#endif
	//Best for single core user I/O
	struct user_ring rx[NUM_MAX_RINGS] __rte_cache_aligned;
	struct tx_user_ring tx[NUM_MAX_RINGS] __rte_cache_aligned;

	unsigned long long base[0] __rte_cache_aligned;
};
#endif //__RTE_MAIO__
