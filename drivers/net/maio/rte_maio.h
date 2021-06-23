#ifndef __RTE_MAIO__
#define __RTE_MAIO__

#include <rte_common.h>

#define MAIO_POISON (0xFEA20FDAU)

#define PAGES_0_PROC_NAME		"/proc/maio/pages_0"
#define MTRX_PROC_NAME			"/proc/maio/mtrx"
#define TX_PROC_NAME			"/proc/maio/tx"
#define NAPI_PROC_NAME			"/proc/maio/napi"
#define MAP_PROC_NAME			"/proc/maio/map"
#define ENABLE_PROC_NAME		"/proc/maio/enable"
#define STOP_PROC_NAME                  "/proc/maio/stop"

#define ETH_MAIO_IFACE_ARG		"iface"
#define ETH_MAIO_QUEUE_COUNT_ARG	"queue_count"

#define PAGE_SIZE			0x1000
#define PAGE_MASK			(~(PAGE_SIZE -1))
#define ALLIGNED_MBUF_OFFSET 		(RTE_CACHE_LINE_SIZE)
#define ETH_MAIO_FRAME_SIZE		PAGE_SIZE
#define ETH_MAIO_MBUF_STRIDE		PAGE_SIZE
#define ETH_MAIO_STRIDE_TOP_MASK	(~(ETH_MAIO_MBUF_STRIDE -1))
#define ETH_MAIO_STRIDE_BOTTOM_MASK	(ETH_MAIO_MBUF_STRIDE -1)
#define ETH_MAIO_DFLT_NUM_DESCS		1024
#define ETH_MAIO_DFLT_DESC_MASK		(ETH_MAIO_DFLT_NUM_DESCS - 1)
#define ETH_MAIO_NUM_INIT_BUFFS		(ETH_MAIO_DFLT_NUM_DESCS * 12)	//12K


#define MAIO_STATUS_VLAN_VALID	0x1
#define MAIO_STATE_TX_COMPLETE	0x2

//#define ETH_MAIO_MBUF_OVERHEAD		0	/*TODO: Velo overhed is set here... */
//#define ETH_MAIO_DATA_HEADROOM 		(ETH_MAIO_MBUF_OVERHEAD + RTE_PKTMBUF_HEADROOM)

#define VC_MD_OFFSET	(PAGE_SIZE -512)
#define NUM_MAX_RINGS	16
#define NAPI_THREAD_IDX        (NUM_MAX_RINGS -1)
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

#define LWM_TRIGGER_COUNT	128	/* get 4K pages back to kernel */
/***************************** SYNC WITH KERNEL DEFINITIONS *******************/
struct io_md {
	uint64_t state;
	uint32_t len;
	uint32_t poison;
	uint16_t vlan_tci;
	uint16_t flags;
};

struct meta_pages_0 {
	uint32_t nr_pages;
	uint32_t stride;
	uint32_t headroom;
	uint32_t flags;
	void *bufs[0];
};

struct q_stat {
	uint32_t pkts;
	uint32_t bytes;
	uint32_t err;
};

struct pmd_stats {
	struct q_stat	rx_queue[NUM_MAX_RINGS];
	struct q_stat	tx_queue[NUM_MAX_RINGS];
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

typedef uint16_t (*eth_napi_tx_burst_t)(void *rxq,
                                   struct rte_mbuf **rx_pkts,
                                   uint16_t nb_pkts);

struct pmd_internals {
	eth_napi_tx_burst_t napi_burst_tx;
	struct user_matrix *matrix;
	struct rte_mempool *mb_pool;
	int if_index;
	int q_cnt;
	char if_name[IFNAMSIZ];
	struct rte_ether_addr eth_addr;
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
	int dev_idx;

};// __rte_cache_aligned;

struct user_matrix {
	/* MUST BE FIRST - used by the Kernel */
	struct common_ring_info info;

	/* user land*/
	struct pmd_stats	stats;
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
