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
#define ETH_MAIO_ZC_TX_ARG		"zc"
#define ETH_MAIO_QUEUE_COUNT_ARG	"queue_count"
#define ETH_MAIO_QUEUE_LEN_ARG		"queue_len"

#define PAGE_SIZE			0x1000
#define PAGE_MASK			(~(PAGE_SIZE -1))
#define ALLIGNED_MBUF_OFFSET 		(RTE_CACHE_LINE_SIZE)
#define ETH_MAIO_FRAME_SIZE		PAGE_SIZE
#define ETH_MAIO_MBUF_STRIDE		PAGE_SIZE
#define ETH_MAIO_STRIDE_TOP_MASK	(~(ETH_MAIO_MBUF_STRIDE -1))
#define ETH_MAIO_STRIDE_BOTTOM_MASK	(ETH_MAIO_MBUF_STRIDE -1)
#define ETH_MAIO_DFLT_DESC_MASK		(ETH_MAIO_DFLT_NUM_DESCS -1)
#define ETH_MAIO_MIN_NUM_DESCS		128
#define ETH_MAIO_MAX_NUM_DESCS		8192
#define ETH_MAIO_DFLT_NUM_DESCS		4096
#define ETH_MAIO_MIN_NUM_RINGS		1
#define ETH_MAIO_MAX_NUM_RINGS		64
#define ETH_MAIO_DFLT_NUM_RINGS		16
#define ETH_DRVR_DFLT_NUM_DESCS		1024


//NR Rings * size + headpages + local core pages (mags * mag size)
#define MAG_SZ				64
#define ETH_MAIO_NUM_INIT_BUFFS(len, num)		((len * num) + num*4*MAG_SZ)
#define ETH_MAIO_NUM_INIT_BUFFS_MAX			ETH_MAIO_NUM_INIT_BUFFS(ETH_DRVR_DFLT_NUM_DESCS, 8)

#define MAIO_STATUS_VLAN_VALID	0x1
#define MAIO_STATE_TX_COMPLETE	0x2

//#define ETH_MAIO_MBUF_OVERHEAD		0	/*TODO: Velo overhed is set here... */
//#define ETH_MAIO_DATA_HEADROOM 		(ETH_MAIO_MBUF_OVERHEAD + RTE_PKTMBUF_HEADROOM)

#define VC_MD_OFFSET		(PAGE_SIZE -64)
#define NUM_MAX_RINGS		16
#define NAPI_THREAD_IDX        (NUM_MAX_RINGS -1)
#define NUM_RING_TYPES		2
#define RE_SZ			(sizeof(void *))

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
#define MAIO_PAGE_NEW           0x10000
#define MAIO_PAGE_REFILL        0x8000
#define MAIO_PAGE_HEAD          0x4000
#define MAIO_PAGE_FREE          0x2000
#define MAIO_PAGE_IO            (MAIO_PAGE_TX|MAIO_PAGE_RX|MAIO_PAGE_NAPI)   // TX|RX|NAPI
#define MAIO_PAGE_NS            0x1000   // storred in the magz
#define MAIO_PAGE_NAPI          0x800   // storred in the magz
#define MAIO_PAGE_TX            0x400   // sent by user
#define MAIO_PAGE_RX            0x200   // alloced from magz - usualy RX
#define MAIO_PAGE_USER          0x100   // page in user space control

typedef unsigned long long int u64;

struct list_head {
	struct rte_mbuf *next;
};

struct io_md {
	/* Kernel Debug */
	uint64_t state;

	/* I/O params */
	uint32_t len;
	uint32_t poison;
	uint16_t vlan_tci;
	uint16_t flags;

	/* DPDK Retransmit support */
	uint16_t tx_cnt;
	uint16_t tx_compl;
	struct io_md *next_frag;
	struct list_head list;
	volatile uint16_t in_transit;
	volatile uint16_t in_transit_dbg;
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
	int q_len;
	int zc;
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
	int q_len;
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
	unsigned long		consumer;
	unsigned long long	*ring;
}; //

struct user_qp_ring {
	struct user_matrix	*mtrx;
	struct user_ring 	rx;
	struct user_ring 	tx;
	int			idx;
	int			tx_fd;
	int			dev_idx;
}__rte_cache_aligned;

struct user_matrix {
	/* MUST BE FIRST - used by the Kernel */
	struct common_ring_info info;

	/* user land*/
	struct pmd_stats	stats;
	//Best for single core user I/O
	int	rx_step;

	struct user_qp_ring rings[NUM_MAX_RINGS] __rte_cache_aligned;

	unsigned long long base[0] __rte_cache_aligned;
};

const char* maio_stat_names[] = {
        "MAIO Prefill		",
#define MAIO_PREFILL			    0
        "MAIO Pushed		",
#define MAIO_PUSH        		    1
        "RX Refill          ",
#define MAIO_RX_REFILL      	    2
        "RX			        ",
#define MAIO_RX        			    3
        "TX			        ",
#define MAIO_TX        			    4
        "DEC			    ",
#define MAIO_DEC        		    5
        "FREE			    ",
#define MAIO_FREE        		    6
        "TX Slow		    ",
#define MAIO_TX_SLOW        		7
        "TX Comp		    ",
#define MAIO_TX_COMP        		8
        "TX CompGC		    ",
#define MAIO_TX_GC_COMP        		9
        "TX Comp Pending	",
#define MAIO_TX_COMP_PENDING      	10
        "TX Comp Stalled	",
#define MAIO_TX_COMP_STALL      	11
        "TX Comp Check		",
#define MAIO_COMP_CHK      		    12
        "TX CPY			    ",
#define MAIO_TX_CPY      		    13
        "TX CPY	ERR		    ",
#define MAIO_TX_CPY_ERR      		14
        "RX Refill Alloc	",
#define MAIO_RX_REFILL_ALLOC		15
        "RX Refill Alloc Fail	",
#define MAIO_RX_REFILL_ALLOC_FAIL	16
        "NAPI		    ",
#define MAIO_NAPI      		        17
        "NAPI Slow	",
#define MAIO_NAPI_SLOW       		18
};

#define NR_MAIO_STATS       (sizeof(maio_stat_names)/sizeof(char *))

struct maio_user_stats {
	uint64_t array[NR_MAIO_STATS];
};

static inline void __set_maio_stat(struct maio_user_stats *stats, int idx, uint64_t val)
{
	stats->array[idx] = val;
}

static inline void __add_maio_stat(struct maio_user_stats *stats, int idx, int val)
{
	stats->array[idx] += val;
}

#endif //__RTE_MAIO__
