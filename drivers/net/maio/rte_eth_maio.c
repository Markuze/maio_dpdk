#include <unistd.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>

/* trace_write block*/
#include <stdarg.h>	//va_...
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>

#include <sys/ioctl.h>
#include <linux/sockios.h>
#include <linux/if_ether.h>
#include <linux/if.h>

#include <arpa/inet.h>

#include <rte_ethdev.h>
#include <rte_ethdev_driver.h>
#include <rte_ethdev_vdev.h>
#include <rte_kvargs.h>
#include <rte_bus_vdev.h>
#include <rte_string_fns.h>
#include <rte_branch_prediction.h>
#include <rte_common.h>
#include <rte_config.h>
#include <rte_dev.h>
#include <rte_eal.h>
#include <rte_ether.h>
#include <rte_lcore.h>
#include <rte_log.h>
#include <rte_memory.h>
#include <rte_memzone.h>
#include <rte_mbuf.h>
#include <rte_malloc.h>
#include <rte_ring.h>

#include "rte_maio.h"

static struct rte_mempool *maio_mb_pool;
static int maio_logtype;

static int zc_tx_set;
#define RTE_MAIO_TX_MAX_FREE_BUF_SZ 64

static _Thread_local struct rte_mbuf *stalled;
static _Thread_local struct rte_mbuf *stalled_tail;
static _Thread_local struct rte_mbuf *comp_ring;
static _Thread_local struct rte_mbuf *comp_ring_tail;
static _Thread_local unsigned long comp_len;
static _Thread_local unsigned long comp_tot;

#define trace_marker 		"/sys/kernel/debug/tracing/trace_marker"
#define trace_marker_alt 	"/sys/kernel/tracing/trace_marker"
static int trace_fd;
static int log_fd;

static struct maio_user_stats maio_stats;
//static void eth_dev_close(struct rte_eth_dev *dev)
static struct rte_eth_dev *static_dev;

#define add_maio_stat(idx, val)	__add_maio_stat(&maio_stats, idx, val)
#define inc_maio_stat(idx)	__add_maio_stat(&maio_stats, idx, 1)

#define WRITE_BUFF_LEN	256

#define COOKIE "--"
#define MAIO_LOG(level, fmt, args...)                 		\
	do {							\
		trace_write(fmt, ##args);				\
	 } while (0)

#define maio_panic(fmt, args...)                                \
    do {							                            \
        dump_maio_stats();                                      \
		trace_write(fmt, ##args);				                \
        fflush(NULL);                                           \
        eth_dev_close(static_dev);                              \
        rte_panic(fmt, ##args);                                 \
	 } while (0)

#define ASSERT(exp)								                \
        do {                                                    \
		if (!(exp)) {							                \
			maio_panic("%s:%d\tassert \"" #exp "\" failed\n",	\
						__FUNCTION__, __LINE__);	            \
        }                                                       \
        } while (0)

static const char *const valid_arguments[] = {
	ETH_MAIO_IFACE_ARG,
	ETH_MAIO_QUEUE_COUNT_ARG,
	ETH_MAIO_QUEUE_LEN_ARG,
	ETH_MAIO_ZC_TX_ARG,
	NULL
};

static const struct rte_eth_link pmd_link = {
        .link_speed = ETH_SPEED_NUM_10G,
        .link_duplex = ETH_LINK_FULL_DUPLEX,
        .link_status = ETH_LINK_DOWN,
        .link_autoneg = ETH_LINK_AUTONEG
};

static void trace_write(const char *fmt, ...)
{
        va_list ap;
        char buf[256];
        int n;

        if (trace_fd < 0)
                return;

        va_start(ap, fmt);
        n = vsnprintf(buf, 256, fmt, ap);
        va_end(ap);

        write(trace_fd, buf, n);
        write(log_fd, buf, n);
}

static inline void dump_maio_stats(void)
{
	unsigned int i = 0;

	for (i = 0; i < NR_MAIO_STATS; i++) {
		trace_write("%s:%lld\n", maio_stat_names[i], maio_stats.array[i]);
	}
}

/* Warning batching is not thread safe. Use TLS instead of static */
static inline void maio_put_mbuf(struct rte_mbuf *mbuf)
{
	if (rte_mbuf_refcnt_read(mbuf) == 1)
		inc_maio_stat(MAIO_FREE);
	else
		inc_maio_stat(MAIO_DEC);

	rte_pktmbuf_free(mbuf);
# if 0
	static struct rte_mbuf *free[RTE_MAIO_TX_MAX_FREE_BUF_SZ];
	static int nr_free;
	struct rte_mbuf *m;

	//TODO: This leaks multiseg packets
	// If rc == 1 queue for freeing, else dec ref.
	if ((m = rte_pktmbuf_prefree_seg(mbuf))) {
		struct io_md *md 	= mbuf2io_md(m);
		if (md->state != MAIO_PAGE_USER)
			dump_md(md);
		free[nr_free++] = m;
	} else {
		MAIO_LOG(ERR, "basically impossible... rc = [%d]\n", rte_mbuf_refcnt_read(mbuf));
	}

	if (unlikely(nr_free == RTE_MAIO_TX_MAX_FREE_BUF_SZ)) {
		//check if safe is raw?

		rte_mempool_put_bulk(maio_mb_pool, (void **)free, nr_free);
		nr_free = 0;
	}
#endif
}

static inline int maio_set_state(const char *state)
{
	int fd, rc = 0;

	if ((fd = open(ENABLE_PROC_NAME, O_RDWR)) < 0) {
		MAIO_LOG(ERR, "Failed to change state %d\n", __LINE__);
		return -ENODEV;
	}

	if (write(fd, state, strlen(state)) != (int)strlen(state)) {
		MAIO_LOG(ERR, "Change state %s[%ld] fd %d\n", state, strlen(state), fd);
		rc = -1;
	} else {
		MAIO_LOG(ERR, "Change state %s[%ld] fd %d\n", state, strlen(state), fd);
	}

	close(fd);

	return rc;
}

/* This function gets called when the current port gets stopped. */
static void eth_dev_stop(struct rte_eth_dev *dev)
{
	char write_buffer[64] = {0};
	struct pmd_internals *internals  = dev->data->dev_private;

	snprintf(write_buffer, 64, "%d %d", 0, internals->if_index);
	maio_set_state(write_buffer);
        dev->data->dev_link.link_status = ETH_LINK_DOWN;
}

static int eth_dev_start(struct rte_eth_dev *dev)
{
	char write_buffer[64] = {0};
	struct pmd_internals *internals  = dev->data->dev_private;

	snprintf(write_buffer, 64, "%d %d", 1, internals->if_index);
	maio_set_state(write_buffer);
	dev->data->dev_link.link_status = ETH_LINK_UP;

	return 0;
}

static void eth_dev_close(struct rte_eth_dev *dev)
{
	struct pmd_internals *internals __rte_unused = dev->data->dev_private;
	char str[16] = "1";
	int fd;


	MAIO_LOG(ERR, "Closing MAIO ethdev on numa socket %u\n", rte_socket_id());

	if ((fd = open(STOP_PROC_NAME, O_RDWR)) < 0) {
	        MAIO_LOG(ERR, "Failed to change str %d\n", __LINE__);
	        return;
	}

	write(fd, str, strlen(str));
	MAIO_LOG(ERR, "Change str %s[%ld] fd %d [%s]\n", str, strlen(str), fd, STOP_PROC_NAME);

	close(fd);

	return;
}

static int eth_dev_configure(struct rte_eth_dev *dev __rte_unused)
{
        return 0;
}

/* TODO: FIXME**/
static int eth_dev_info(struct rte_eth_dev *dev, struct rte_eth_dev_info *dev_info)
{
	struct pmd_internals *internals = dev->data->dev_private;

	dev_info->if_index = internals->if_index;
	dev_info->max_mac_addrs = 1;
	dev_info->max_rx_pktlen = ETH_FRAME_LEN;
	dev_info->max_rx_queues = ETH_MAIO_DFLT_NUM_RINGS;
	dev_info->max_tx_queues = ETH_MAIO_DFLT_NUM_RINGS;

	dev_info->min_mtu = RTE_ETHER_MIN_MTU;
	dev_info->max_mtu = ETH_MAX_MTU;

	dev_info->default_rxportconf.nb_queues = 1;
	dev_info->default_txportconf.nb_queues = 1;
	dev_info->default_rxportconf.ring_size = ETH_MAIO_DFLT_NUM_DESCS;
	dev_info->default_txportconf.ring_size = ETH_MAIO_DFLT_NUM_DESCS;

/*
        dev_info->tx_offload_capa = DEV_TX_OFFLOAD_MULTI_SEGS |
                DEV_TX_OFFLOAD_VLAN_INSERT;
*/
	return 0;
}

static int eth_dev_mtu_set(struct rte_eth_dev *dev, uint16_t mtu)
{
	struct pmd_internals *internals = dev->data->dev_private;
	struct ifreq ifr = { .ifr_mtu = mtu };
	int ret;
	int s;

	s = socket(PF_INET, SOCK_DGRAM, 0);
	if (s < 0)
		return -EINVAL;

	strlcpy(ifr.ifr_name, internals->if_name, IFNAMSIZ);
	ret = ioctl(s, SIOCSIFMTU, &ifr);
	close(s);

	return (ret < 0) ? -errno : 0;
}

static int eth_dev_change_flags(char *if_name, uint32_t flags, uint32_t mask)
{
	struct ifreq ifr;
	int ret = 0;
	int s;

	s = socket(PF_INET, SOCK_DGRAM, 0);
	if (s < 0)
		return -errno;

	strlcpy(ifr.ifr_name, if_name, IFNAMSIZ);
	if (ioctl(s, SIOCGIFFLAGS, &ifr) < 0) {
		ret = -errno;
		goto out;
	}
	ifr.ifr_flags &= mask;
	ifr.ifr_flags |= flags;
	if (ioctl(s, SIOCSIFFLAGS, &ifr) < 0) {
		ret = -errno;
		goto out;
	}
out:
	close(s);
	return ret;
}

static int eth_dev_promiscuous_enable(struct rte_eth_dev *dev)
{
	struct pmd_internals *internals = dev->data->dev_private;

	return eth_dev_change_flags(internals->if_name, IFF_PROMISC, ~0);
}

static int eth_dev_promiscuous_disable(struct rte_eth_dev *dev)
{
	struct pmd_internals *internals = dev->data->dev_private;

	return eth_dev_change_flags(internals->if_name, 0, ~IFF_PROMISC);
}

/*TODO: Fixup bin search*/
static inline int maio_map_memory(void *base_addr, int nr_pages)
{
	int map_proc, len;
	char write_buffer[64] = {0};

	if ((map_proc = open(MAP_PROC_NAME, O_RDWR)) < 0) {
		MAIO_LOG(ERR, "Failed to init internals %d\n", __LINE__);
		return -ENODEV;
	}

	printf(">>> base_addr %p len %d [2MB pages]\n", base_addr, nr_pages);
	len  = snprintf(write_buffer, 64, "%llx %u\n", (unsigned long long)base_addr, nr_pages);
	len = write(map_proc, write_buffer, len);

	printf(">>> Sent %s [2MB = %x]\n", write_buffer, (1<<21));

	close(map_proc);

	return 0;
}

static unsigned long get_msl_len(const struct rte_memseg_list *msl, unsigned long len)
{
	struct rte_memseg *memseg = rte_mem_virt2memseg(RTE_PTR_ADD(msl->base_va, len -1), msl);
	unsigned long populated = memseg ? memseg->len : 0;

	if (populated)
		return len;

	if (len == 1)
		return len;

	return get_msl_len(msl, len >> 1);
}

static int prep_map_mem(const struct rte_memseg_list *msl, void *arg __rte_unused)
{
	struct rte_memseg *memseg = rte_mem_virt2memseg(msl->base_va, msl);
	unsigned long len = memseg ? memseg->len : 0;

	if (!len) {
		MAIO_LOG(ERR, "EMPTY: msl: %p - %lx sz 0x%lx len %lu\n", msl->base_va, (unsigned long)msl->base_va + len, msl->page_sz, len >> 21);
		return 0;
	}
	len = get_msl_len(msl, msl->len);
	MAIO_LOG(ERR, "msl: %p - %lx sz 0x%lx len %lu\n", msl->base_va, (unsigned long)msl->base_va + len, msl->page_sz, len >> 21);

	maio_map_memory(msl->base_va, (len >> 21));
        return 0;
}

static inline uint64_t get_base_addr(struct rte_mempool *mp)
{
	struct rte_mempool_memhdr *memhdr;

	memhdr = STAILQ_FIRST(&mp->mem_list);
//	return (uint64_t)memhdr->addr & ~(getpagesize() - 1);
	return (uint64_t)memhdr->addr & ~(HP_MASK);
}

static inline int maio_map_mbuf(struct rte_mempool *mb_pool)
{
	int i, proc, len;
	size_t pages_sz;
	struct meta_pages_0 *pages;
	struct rte_mbuf **mbufs;

	len = min(ETH_MAIO_NUM_INIT_BUFFS_MAX, mb_pool->populated_size >> 1);

	mbufs = rte_zmalloc_socket(NULL, sizeof(struct rte_mbuf *) * len,
						RTE_CACHE_LINE_SIZE, rte_socket_id());
	pages_sz =  sizeof(struct meta_pages_0) + (len *  sizeof(void *));
	fprintf(stderr, "%s}%lu = %lu + (%u  * %lu)\n", __FUNCTION__, pages_sz , sizeof(struct meta_pages_0) ,len , sizeof(void *));
	pages = rte_zmalloc_socket(NULL, pages_sz, RTE_CACHE_LINE_SIZE, rte_socket_id());

	MAIO_LOG(ERR, "push mem to Kernel %d, allocating %d mbufs [%d pages]\n", __LINE__, len, len);
        if (rte_pktmbuf_alloc_bulk(mb_pool, mbufs, len)) {
               	MAIO_LOG(ERR, "Failed to get enough buffers for fq.\n");
		return -ENOMEM;
        }
	add_maio_stat(MAIO_PUSH, len);
#if 1
	/* TODO: Figure out why not main msl?!?! MAPPING MBUF MEMORY */
	MAIO_LOG(ERR, "/* TODO: Figure out why not main msl?!?! MAPPING MBUF MEMORY */\n");
	maio_map_memory((void *)get_base_addr(mb_pool), DIV_ROUND_UP_HP((mb_pool->populated_size * ETH_MAIO_MBUF_STRIDE)));
#endif
	for (i = 0; i < len; i++) {
#if 0
		if ((unsigned long long)mbufs[i] & ETH_MAIO_MBUF_STRIDE) {
			continue;
		}
#endif
		pages->bufs[i] = mbufs[i];
		ASSERT(((unsigned long)mbufs[i] & ETH_MAIO_STRIDE_BOTTOM_MASK)==RTE_CACHE_LINE_SIZE);
#if 0
		if (!(i & 0x1ff)) {
			MAIO_LOG(ERR, "mbuf %p[%lld] data %p[%lld]\n", pages->bufs[i],
				(unsigned long long)pages->bufs[i] & ~ETH_MAIO_STRIDE_MASK,
				mbufs[i]->buf_addr,
				(unsigned long long)mbufs[i]->buf_addr & ~ETH_MAIO_STRIDE_MASK);
		}
#endif
	}

	/* TODO: Check if region mapped - and mapp anew (af_xdp shit)
		* add mtt tree in kernel.
		* have mtt tree in user land - msl? - debug more msl.
		* mapp non mapped buffers.
	*/
	if ((proc = open(PAGES_0_PROC_NAME, O_RDWR)) < 0) {
		MAIO_LOG(ERR, "Failed to init internals %d\n", __LINE__);
		return -ENODEV;
	}

	pages->nr_pages = len;
	pages->stride   = ETH_MAIO_MBUF_STRIDE;	//TODO: get it from mbuf
	pages->headroom = (uint64_t)mbufs[0]->buf_addr & ETH_MAIO_STRIDE_BOTTOM_MASK;
	pages->flags    = 0xC0CE;
	i = write(proc, pages, pages_sz);
	fprintf(stderr, "%s: sent to %s [%lu] first addr %p of %d [%d]\n", __FUNCTION__, PAGES_0_PROC_NAME, pages_sz, pages->bufs[0], len, i);

	rte_free(mbufs);
	rte_free(pages);

	if (i) {
		fprintf(stderr, "FAILED TO POPULATE MAG!!!\n");
		return i;
	}

	maio_mb_pool = mb_pool;
	return 0;
}

static void maio_prefill_rx_rings(struct user_matrix *matrix);

static int eth_rx_queue_setup(struct rte_eth_dev *dev,
				uint16_t rx_queue_id,
				uint16_t nb_rx_desc __rte_unused,
				unsigned int socket_id __rte_unused,
				const struct rte_eth_rxconf *rx_conf __rte_unused,
				struct rte_mempool *mb_pool)
{
	struct pmd_internals *internals = dev->data->dev_private;
#if 0
        uint32_t buf_size, data_size;
	int ret = 0;

        /* Now get the space available for data in the mbuf */
        buf_size = rte_pktmbuf_data_room_size(mb_pool);
        data_size = 1514;

        if (data_size > buf_size) {
                MAIO_LOG(ERR, "%s: %d bytes will not fit in mbuf (%d bytes)\n",
                        dev->device->name, data_size, buf_size);
                ret = -ENOMEM;
                goto err;
        }
	MAIO_LOG(ERR, "%s: %d bytes will fit in mbuf (%d bytes)\n",
		dev->device->name, data_size, buf_size);
#endif
	MAIO_LOG(ERR, "%s: init %d\n", __FUNCTION__, rx_queue_id);
	maio_map_mbuf(mb_pool);
	internals->matrix->rx_step++;
	internals->matrix->rings[rx_queue_id].mtrx = internals->matrix;
	internals->matrix->rings[rx_queue_id].idx = rx_queue_id;

	dev->data->rx_queues[rx_queue_id] = &internals->matrix->rings[rx_queue_id];

	maio_prefill_rx_rings(internals->matrix);

	MAIO_LOG(ERR, "OUT %s: init %d (s:%d)\n", __FUNCTION__, rx_queue_id, internals->matrix->rx_step);
	return 0;
#if 0
err:
	return ret;
#endif
}

static int eth_tx_queue_setup(struct rte_eth_dev *dev,
				uint16_t tx_queue_id,
				uint16_t nb_tx_desc __rte_unused,
				unsigned int socket_id __rte_unused,
				const struct rte_eth_txconf *tx_conf __rte_unused)
{
	static int tx_proc;
	static int napi_proc;
	struct pmd_internals *internals  = dev->data->dev_private;

	MAIO_LOG(ERR, "Init TX Ring %d\n", tx_queue_id);
	internals->matrix->rings[tx_queue_id].idx = tx_queue_id;
	internals->matrix->rings[tx_queue_id].mtrx = internals->matrix;
	dev->data->tx_queues[tx_queue_id] = &internals->matrix->rings[tx_queue_id];

	if (!tx_proc) {
		if ((tx_proc = open(TX_PROC_NAME, O_RDWR)) < 0) {
			MAIO_LOG(ERR, "Failed to init internals %d\n", __LINE__);
			return -ENODEV;
		}
	}

	if (!napi_proc) {
		if ((napi_proc = open(NAPI_PROC_NAME, O_RDWR)) < 0) {
			MAIO_LOG(ERR, "Failed to init internals %d\n", __LINE__);
			return -ENODEV;
		}
	}

	internals->matrix->rings[tx_queue_id].tx_fd = tx_proc;
	internals->matrix->rings[tx_queue_id].dev_idx = internals->if_index;

	internals->matrix->rings[NAPI_THREAD_IDX].tx_fd = napi_proc;
	internals->matrix->rings[NAPI_THREAD_IDX].dev_idx = internals->if_index;

	MAIO_LOG(ERR, "OUT %s: init %d\n", __FUNCTION__, tx_queue_id);
	return 0;
}

static void eth_queue_release(void *q __rte_unused)
{
}

static int eth_link_update(struct rte_eth_dev *dev __rte_unused,
				int wait_to_complete __rte_unused)
{
	return 0;
}

static int eth_stats_get(struct rte_eth_dev *dev, struct rte_eth_stats *stats)
{
	unsigned i, imax;
        unsigned long rx_total = 0, tx_total = 0, tx_err_total = 0;
        unsigned long rx_bytes_total = 0, tx_bytes_total = 0;
        const struct pmd_internals *internal = dev->data->dev_private;

	struct pmd_stats *pmd_stats = (internal->matrix) ? &internal->matrix->stats
					: NULL;
	if (!pmd_stats) {
		memset(stats, 0, sizeof(*stats));
		return 0;
	}

        imax = (internal->matrix->info.nr_rx_rings < RTE_ETHDEV_QUEUE_STAT_CNTRS ?
                internal->matrix->info.nr_rx_rings : RTE_ETHDEV_QUEUE_STAT_CNTRS);
        for (i = 0; i < imax; i++) {
                stats->q_ipackets[i]	= pmd_stats->rx_queue[i].pkts;
                stats->q_ibytes[i]	= pmd_stats->rx_queue[i].bytes;
                rx_total		+= stats->q_ipackets[i];
                rx_bytes_total		+= stats->q_ibytes[i];
        }

        imax = (internal->matrix->info.nr_tx_rings < RTE_ETHDEV_QUEUE_STAT_CNTRS ?
                internal->matrix->info.nr_tx_rings : RTE_ETHDEV_QUEUE_STAT_CNTRS);
        for (i = 0; i < imax; i++) {
                stats->q_opackets[i]	= pmd_stats->tx_queue[i].pkts;
                stats->q_obytes[i]	= pmd_stats->tx_queue[i].bytes;
                tx_err_total 		+= pmd_stats->tx_queue[i].err;
                tx_total 		+= stats->q_opackets[i];
                tx_bytes_total 		+= stats->q_obytes[i];
        }

        stats->ipackets	= rx_total;
        stats->ibytes	= rx_bytes_total;
        stats->opackets	= tx_total;
        stats->oerrors	= tx_err_total;
        stats->obytes	= tx_bytes_total;

	return 0;
}

static int eth_stats_reset(struct rte_eth_dev *dev)
{
	struct pmd_internals *internal = dev->data->dev_private;
	struct pmd_stats *pmd_stats = (internal->matrix) ? &internal->matrix->stats
					: NULL;
	if (!pmd_stats)
		goto out;

	memset(pmd_stats, 0, sizeof(*pmd_stats));
out:
	return 0;
}

static const struct eth_dev_ops ops = {
	.dev_start = eth_dev_start,
	.dev_stop = eth_dev_stop,
	.dev_close = eth_dev_close,
	.dev_configure = eth_dev_configure,
	.dev_infos_get = eth_dev_info,
	.mtu_set = eth_dev_mtu_set,
	.promiscuous_enable = eth_dev_promiscuous_enable,
	.promiscuous_disable = eth_dev_promiscuous_disable,
	.rx_queue_setup = eth_rx_queue_setup,
	.tx_queue_setup = eth_tx_queue_setup,
	.rx_queue_release = eth_queue_release,
	.tx_queue_release = eth_queue_release,
	.link_update = eth_link_update,
	.stats_get = eth_stats_get,
	.stats_reset = eth_stats_reset,
};

static inline void show_io(struct rte_mbuf *mbuf, const char* str)
{
	struct rte_ether_hdr *eth;
	struct rte_ipv4_hdr *ip;
	char write_buffer[WRITE_BUFF_LEN], src_ip[INET_ADDRSTRLEN], dst_ip[INET_ADDRSTRLEN];
	int len, cur = 0;

	eth 	= rte_pktmbuf_mtod(mbuf, struct rte_ether_hdr *);
	ip	= (struct rte_ipv4_hdr *)&eth[1];

	//len = snprintf(&write_buffer[cur], WRITE_BUFF_LEN - cur,"%s\n", str);
	//cur += len;
	len = snprintf(&write_buffer[cur], WRITE_BUFF_LEN - cur, "%s\t:IN type: 0x%x: len %d \n\t:D_MAC address: %02X:%02X:%02X:%02X:%02X:%02X\n",
			str,
			rte_cpu_to_be_16(eth->ether_type),
			rte_pktmbuf_pkt_len(mbuf),
			eth->d_addr.addr_bytes[0],
			eth->d_addr.addr_bytes[1],
			eth->d_addr.addr_bytes[2],
			eth->d_addr.addr_bytes[3],
			eth->d_addr.addr_bytes[4],
			eth->d_addr.addr_bytes[5]);
	cur += len;
	len = snprintf(&write_buffer[cur], WRITE_BUFF_LEN - cur, "%s\t:S_MAC address: %02X:%02X:%02X:%02X:%02X:%02X\n",
			str,
			eth->s_addr.addr_bytes[0],
			eth->s_addr.addr_bytes[1],
			eth->s_addr.addr_bytes[2],
			eth->s_addr.addr_bytes[3],
			eth->s_addr.addr_bytes[4],
			eth->s_addr.addr_bytes[5]);
	cur += len;

	inet_ntop(AF_INET, &ip->src_addr, src_ip, INET_ADDRSTRLEN);
	inet_ntop(AF_INET, &ip->dst_addr, dst_ip, INET_ADDRSTRLEN);

	len = snprintf(&write_buffer[cur], WRITE_BUFF_LEN - cur,"%s:\tv%d next %d:SIP: %s DIP: %s\n",
			str, (ip->version_ihl >> 4) & 0xF, ip->next_proto_id,
			src_ip, dst_ip);
    cur += len;
    write(trace_fd, write_buffer, cur);
}

#define mbuf2list(addr)	 &mbuf2io_md(addr)->list
#define void2mbuf(addr)	 (struct rte_mbuf *)(((unsigned long long)addr & ETH_MAIO_STRIDE_TOP_MASK) + ALLIGNED_MBUF_OFFSET)
#define void2io_md(addr) (struct io_md *)(((unsigned long long)addr & ETH_MAIO_STRIDE_TOP_MASK) + VC_MD_OFFSET)

static inline struct io_md* mbuf2io_md(struct rte_mbuf *mbuf)
{
	uint64_t md = (uint64_t)rte_pktmbuf_mtod(mbuf, void *);
	md = md & PAGE_MASK;
	md += VC_MD_OFFSET;

	return (struct io_md *)md;
}

static inline void __dump_md(struct io_md *md, int line)
{
		MAIO_LOG(ERR, "%d: [%llx]state %lx transit %d dbg %d\n", line, ((u64)md & PAGE_MASK),
				md->state, md->in_transit, md->in_transit_dbg);
}

#define dump_md(m)	__dump_md(m, __LINE__)

#define SHOW_IO(...)
//#define SHOW_IO(a,b)	show_io(a,b);

#define is_rx_refill_page(p)			(((unsigned long)p) & 0x1)
#define post_rx_ring_entry(r, p)		(r)->ring[(r)->consumer & ETH_MAIO_DFLT_DESC_MASK] = ((unsigned long)p | 0x1)
#define rx_ring_entry(r)			(r)->ring[(r)->consumer & ETH_MAIO_DFLT_DESC_MASK]
#define tx_ring_entry(r)			(r)->ring[(r)->consumer & ETH_MAIO_DFLT_DESC_MASK]
#define post_tx_ring_entry(r, p)		(r)->ring[(r)->consumer++ & ETH_MAIO_DFLT_DESC_MASK] = ((unsigned long)p | 0x1)
#define advance_rx_ring_clear(r)		(r)->ring[(r)->consumer++ & ETH_MAIO_DFLT_DESC_MASK] = 0
#define advance_rx_ring(r)			(r)->consumer++

#define REFILL_NUM	64
static inline void post_rx_ring_safe(struct user_ring *ring, struct rte_mbuf *mbuf)
{
	struct io_md *md = mbuf2io_md(mbuf);

	if (md->state && md->state != MAIO_PAGE_USER) {
		dump_md(md);
		ASSERT(md->state == MAIO_PAGE_USER);
	} else {
		md->state = MAIO_PAGE_REFILL;
	}
    rte_wmb();
	post_rx_ring_entry(ring, mbuf);
}

static inline void post_tx_ring_safe(struct user_ring *ring, void *addr)
{
	struct io_md *md = void2io_md(addr);

	////in some case PAGE_TX is also valid
	if (md->state && md->state != MAIO_PAGE_USER) {
		dump_md(md);
		ASSERT((md->state & (MAIO_PAGE_USER|MAIO_PAGE_TX)));
	}
	post_tx_ring_entry(ring, addr);
}

static inline int is_head_page(void *buf)
{
	unsigned long long addr = (unsigned long long)buf;
	addr &= PAGE_MASK & HP_MASK;

	return !addr;
}

static inline void post_refill_rx_page(struct user_ring *ring)
{
	static _Thread_local struct rte_mbuf *mbufs[REFILL_NUM];
	static _Thread_local int idx;

	if (! idx) {
		if (rte_pktmbuf_alloc_bulk(maio_mb_pool, mbufs, REFILL_NUM)) {
			MAIO_LOG(ERR, "Failed to get enough buffers on RX Refill!.\n");
            add_maio_stat(MAIO_RX_REFILL_ALLOC_FAIL, REFILL_NUM);
			//dump_maio_stats();
			maio_panic("Hemm - %lu/%lu %d\n", comp_len, comp_tot, __LINE__);
			return;
		}
		add_maio_stat(MAIO_RX_REFILL_ALLOC, REFILL_NUM);
	}

    inc_maio_stat(MAIO_RX_REFILL);
	post_rx_ring_safe(ring, mbufs[idx]);

	mbufs[idx] = 0;
	++idx;
	idx &= (REFILL_NUM -1);
}

static inline struct rte_mbuf *maio_addr2mbuf(uint64_t addr)
{
	struct rte_mbuf *mbuf = (struct rte_mbuf *)((addr & ETH_MAIO_STRIDE_TOP_MASK) + ALLIGNED_MBUF_OFFSET);

	ASSERT(addr > (uint64_t)mbuf->buf_addr);
	mbuf->data_off = addr - (uint64_t)mbuf->buf_addr;
	return mbuf;
}

#if 0
static int random_refill(void)
{
	static unsigned long	cnt;
	cnt++;

	if (lwm_mark_trigger)
		return 0;
	if (!(cnt & 0xffff)) {
		lwm_mark_trigger = 32;
	}

	return 0;
}

static int random_drop(void)
{
	static unsigned long	cnt;
	static unsigned long	dropped;

	cnt++;

	if (lwm_mark_trigger)
		return 0;

	if (!(cnt & 0x1f)) {
		dropped++;
		if (!(dropped & 0xfff))
			fprintf(stderr,"Dropped %lu [%lu]\n", dropped, cnt);
		return 1;
	}

	return 0;
}
#endif

static inline int addr_wm_signal(uint64_t addr)
{
	struct rte_mbuf *mbuf;

	//page aligned address is a refill packet -- Head Page
	if (!(addr & ETH_MAIO_STRIDE_BOTTOM_MASK)) {
		mbuf = (struct rte_mbuf *)((addr & ETH_MAIO_STRIDE_TOP_MASK) + ALLIGNED_MBUF_OFFSET);
		/*TODO: Add rte_pktmbuf_free_bulk optimization */
		maio_put_mbuf(mbuf);
		return 1;
	}

# if 0
	random_refill();
	/* usefull for testing LWM */
	if (random_drop()) {
		mbuf = (struct rte_mbuf *)((addr & ETH_MAIO_STRIDE_TOP_MASK) + ALLIGNED_MBUF_OFFSET);
		/*TODO: Add rte_pktmbuf_free_bulk optimization */
		rte_pktmbuf_free(mbuf);
		return 1;
	}
#endif
	return 0;
}

static inline struct rte_mbuf **poll_maio_ring(struct user_ring *ring,
						struct rte_mbuf **bufs,
						uint16_t *cnt, uint32_t *bytes, uint16_t nb_pkts)
{
	int i = 0;
	uint32_t byte_cnt = 0;
	uint64_t addr;

	while ((addr = rx_ring_entry(ring)))  {
		struct rte_mbuf *mbuf;
		struct io_md *md;

		//Check if the page is an RX refill page
		if (is_rx_refill_page(addr))
			break;

		mbuf 	= maio_addr2mbuf(addr);
		//printf("Received[%ld] 0x%lx - mbuf %lx\n", ring->consumer, addr, mbuf);
		//printf("mbuf %p: data %p offset %d\n", mbuf, mbuf->buf_addr, mbuf->data_off);
		md 	= mbuf2io_md(mbuf);

		post_refill_rx_page(ring);

		rte_wmb();

		advance_rx_ring(ring);
		ASSERT(mbuf->pool == maio_mb_pool);
		ASSERT(md->poison == MAIO_POISON);
		rte_pktmbuf_pkt_len(mbuf) = md->len;
		rte_pktmbuf_data_len(mbuf) = md->len;

		/* check for vlan info */
		if (md->flags & MAIO_STATUS_VLAN_VALID) {
			mbuf->vlan_tci 	= md->vlan_tci;
			mbuf->ol_flags |= (PKT_RX_VLAN | PKT_RX_VLAN_STRIPPED);
			show_io(mbuf, "RX");
		}

		bufs[i++] = mbuf;
		byte_cnt += md->len;

		SHOW_IO(mbuf, "RX");

		if (--nb_pkts)
			break;
	}
	*cnt = i;
	*bytes = byte_cnt;
	return &bufs[i];
}

static inline int prefill_maio_ring(struct user_ring *ring)
{
	int i = 0;
	uint64_t addr;

	while (! (addr = rx_ring_entry(ring)))  {
		post_refill_rx_page(ring);
		advance_rx_ring(ring);
		++i;
	}
	return i;
}


static inline void maio_prefill_rx_rings(struct user_matrix *matrix)
{
	int i;

	for (i = 0; i < NUM_MAX_RINGS; i++) {
		int cnt = prefill_maio_ring(&matrix->rings[i].rx);
		if (cnt)
			MAIO_LOG(ERR, "Prefilled %d pages on ring %d\n", cnt, i);
			add_maio_stat(MAIO_PREFILL, cnt);
	}
}

static uint16_t eth_maio_rx(void *queue,
				struct rte_mbuf **bufs,
				uint16_t nb_pkts)
{
	int i;
	uint32_t bytes;
	uint16_t cnt = 0;
	uint16_t rcv = 0;
	struct user_qp_ring *ring = queue;
	struct user_matrix *matrix = ring->mtrx;
	struct pmd_stats *stats = &matrix->stats;

	for (i = ring->idx; i < NUM_MAX_RINGS; i += matrix->rx_step) {
		ring = &matrix->rings[i];
		bufs = poll_maio_ring(&ring->rx, bufs, &cnt, &bytes, nb_pkts);
		nb_pkts -= cnt;
		rcv 	+= cnt;

		stats->rx_queue[i].pkts += cnt;
		stats->rx_queue[i].bytes += bytes;

		add_maio_stat(MAIO_RX, cnt);
		if (!nb_pkts)
			break;
	}
	return rcv;
}

static inline int maio_tx_complete(struct rte_mbuf *mbuf)
{
	struct io_md *md;

	if (!mbuf)
		return 0;

	md = mbuf2io_md(mbuf);
#if 0
	if (md->in_transit)
		dump_md(md);
#endif
	return !md->in_transit;
}

static inline struct rte_mbuf *remove_stalled_head(void)
{
	struct rte_mbuf *m = stalled;
	struct list_head *list = mbuf2list(m);

	stalled = list->next;
	list->next = NULL;

	return m;
}

static inline struct rte_mbuf *remove_comp_ring_head(void)
{
	struct rte_mbuf *m = comp_ring;
	struct list_head *list = mbuf2list(m);

	comp_ring = list->next;
	list->next = NULL;

	--comp_len;
	++comp_tot;

	return m;
}

static inline void enque_stalled(struct rte_mbuf *mbuf)
{
	struct list_head *list	= mbuf2list(mbuf);

	list->next = NULL;

	if (stalled == NULL) {
		stalled	= mbuf;
	} else {
		list		= mbuf2list(stalled_tail);
		list->next 	= mbuf;
	}

	stalled_tail	= mbuf;

	/* drain complete TX buffers */
	while (maio_tx_complete(stalled)) {
		struct rte_mbuf *m = remove_stalled_head();
		inc_maio_stat(MAIO_TX_GC_COMP);
		inc_maio_stat(MAIO_TX_COMP);
		maio_put_mbuf(m);
	}
}

static inline void enque_mbuf(struct rte_mbuf *mbuf)
{
	struct list_head *list = mbuf2list(mbuf);

	if (maio_tx_complete(mbuf)) {
		maio_put_mbuf(mbuf);
		return;
	}

	list->next = NULL;

	if (comp_ring == NULL) {
		comp_ring	= mbuf;
		if (comp_len)
			maio_panic("Comp Len is wrong %lu/%lu\n", comp_len, comp_tot);
	} else {
		list		= mbuf2list(comp_ring_tail);
		list->next 	= mbuf;
	}
	++comp_len;
	comp_ring_tail	= mbuf;
	inc_maio_stat(MAIO_TX_COMP_PENDING);
drain:
	/* drain complete TX buffers */
	while (maio_tx_complete(comp_ring)) {
		struct rte_mbuf *m = remove_comp_ring_head();
		inc_maio_stat(MAIO_TX_COMP);
		maio_put_mbuf(m);
	}

	if (comp_len > (ETH_MAIO_DFLT_NUM_DESCS << 1)) {
		struct rte_mbuf *m 	= remove_comp_ring_head();
		struct io_md *md	= mbuf2io_md(m);
		if (md->state == MAIO_PAGE_USER)  {
			maio_put_mbuf(m);
			inc_maio_stat(MAIO_COMP_CHK);
			inc_maio_stat(MAIO_TX_COMP);
		} else {
			enque_stalled(m);
			inc_maio_stat(MAIO_TX_COMP_STALL);
		}
		goto drain;
	}

	return;
}

#if 0
/* Kernel should check for LOCKED flag on free and set status instead of reusing */
/* TODO: consider using different thread for refill tasks (just change the TX ring from 0/NAPI)*/
static inline void enque_mbuf(struct rte_mbuf *mbuf)
{
	if (unlikely(!tx_comp_head)) {
		tx_comp_head = mbuf;
		tx_comp_tail = mbuf;
		return;
	}

	tx_comp_tail->next = mbuf;
	tx_comp_tail = mbuf;

	/* drain complete TX buffers */
	while (maio_tx_complete(tx_comp_head)) {
		struct rte_mbuf *m = tx_comp_head;
		tx_comp_head = tx_comp_head->next;
		maio_put_mbuf(m);
	}
	return;
}
#endif

static inline struct rte_mbuf *get_cpy_mbuf(struct rte_mbuf *mbuf)
{
	struct rte_mbuf *new = rte_pktmbuf_copy(mbuf, maio_mb_pool, 0, UINT32_MAX);

	maio_put_mbuf(mbuf);

	if (!new)
		return NULL;

	return new;
}

static inline int post_maio_ring(struct user_ring *ring,
					struct rte_mbuf **bufs,
					uint16_t nb_pkts, struct q_stat *tx_queue)
{
	uint32_t bytes = 0;
	uint16_t flags = 0;
	int i = 0;

	while (nb_pkts--)  {
		struct rte_mbuf *mbuf = NULL, *m_seg;
		struct rte_mbuf *tx_mbuf = *bufs;
		struct io_md *md, *seg_md;
		unsigned long long comp_addr = tx_ring_entry(ring);

		if (comp_addr & 0x1) {
			//This is a kernel owned buffer, try again later.
			goto stats;
		} else {
			if (likely(comp_addr)) {
				struct rte_mbuf *comp_mbuf = void2mbuf(comp_addr);
				struct io_md *comp_md 	= mbuf2io_md(comp_mbuf);

				++comp_md->tx_compl;

				if (comp_md->tx_cnt == comp_md->tx_compl) {
					enque_mbuf(comp_mbuf);
				} else {
					// if tx_cnt != tx_compl - packet was sent more then once.
					// We should be just dec_ref, and only when  tx_cnt != tx_compl enque once.
					maio_put_mbuf(comp_mbuf);
		                }
			}
		}

		SHOW_IO(tx_mbuf, "cpyTX");
		ASSERT(tx_mbuf->pool == maio_mb_pool);

		if (likely(zc_tx_set)) {
			mbuf = tx_mbuf;
		} else {
			mbuf = get_cpy_mbuf(tx_mbuf);
			if (unlikely(!mbuf)) {
				inc_maio_stat(MAIO_TX_CPY_ERR);
				goto stats;
			} else {
				inc_maio_stat(MAIO_TX_CPY);
			}
		}

		m_seg = mbuf;
		do {
			seg_md 	= mbuf2io_md(m_seg);

			seg_md->flags	= flags;
			seg_md->poison	= MAIO_POISON;
			seg_md->len	= rte_pktmbuf_data_len(m_seg);

			m_seg = m_seg->next;
			if (m_seg)
				seg_md->next_frag = rte_pktmbuf_mtod(m_seg, void *);
			else
				seg_md->next_frag = NULL;
		} while (m_seg != NULL);
		/************************/

		md = mbuf2io_md(mbuf);
		++md->tx_cnt;

		/* insert vlan info if necessary */
		if (mbuf->ol_flags & PKT_TX_VLAN_PKT) {
			md->flags	|= MAIO_STATUS_VLAN_VALID;
			md->vlan_tci	= mbuf->vlan_tci;
		}
		/* Just make sure that the ring is updated only *after* all parameters are set */
		rte_wmb();

		post_tx_ring_safe(ring, rte_pktmbuf_mtod(mbuf, void *));
		bufs++;

		i++;
		bytes += md->len;
	}
stats:
	tx_queue->pkts	+= i;
	tx_queue->bytes += bytes;

	return i;
}

static uint16_t eth_maio_napi(void *queue,
				struct rte_mbuf **bufs,
				uint16_t nb_pkts)
{
	struct user_qp_ring *ring = queue;
	struct pmd_stats *stats = &ring->mtrx->stats;
	char write_buffer[WRITE_BUFF_LEN] = {0};
	int len, idx, rc = nb_pkts;

	idx 	= NAPI_THREAD_IDX;
	ring 	= &ring->mtrx->rings[idx];

	rc = post_maio_ring(&ring->tx, bufs, nb_pkts, &stats->tx_queue[idx]);
	/* Ring DoorBell -- SysCall */
	len = snprintf(write_buffer, WRITE_BUFF_LEN, "%d %d\n", ring->dev_idx, idx);
	len = write(ring->tx_fd, write_buffer, len);

	add_maio_stat(MAIO_NAPI, rc);
	if (unlikely(nb_pkts - rc))
		add_maio_stat(MAIO_NAPI_SLOW, nb_pkts - rc);
	return rc;
}
static uint16_t eth_maio_napi_wrapper(void *queue,
					struct rte_mbuf **bufs,
					uint16_t nb_pkts)
{
	struct user_matrix *matrix	= queue;
	struct user_qp_ring *ring 	= &matrix->rings[NAPI_THREAD_IDX];

	return eth_maio_napi(ring, bufs, nb_pkts);
}

static uint16_t eth_maio_tx(void *queue,
				struct rte_mbuf **bufs,
				uint16_t nb_pkts)
{
	struct user_qp_ring *ring = queue;
	struct pmd_stats *stats = &ring->mtrx->stats;
	char write_buffer[WRITE_BUFF_LEN] = {0};
	int len, idx, rc = nb_pkts;
	idx = ring->idx;

	rc = post_maio_ring(&ring->tx, bufs, nb_pkts, &stats->tx_queue[idx]);
	/* Ring DoorBell -- SysCall */
	len = snprintf(write_buffer, WRITE_BUFF_LEN, "%d %d\n", ring->dev_idx, idx);
	len = write(ring->tx_fd, write_buffer, len);

	//bufs = &bufs[rc];

	add_maio_stat(MAIO_TX, rc);
	if (unlikely(nb_pkts - rc))
		add_maio_stat(MAIO_TX_SLOW, nb_pkts - rc);
	return rc;
}

static inline int get_iface_info(const char *if_name, struct rte_ether_addr *eth_addr, int *if_index)
{
	int rc = 0;
        struct ifreq ifr;
        int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);

        if (sock < 0)
                return -1;

        strlcpy(ifr.ifr_name, if_name, IFNAMSIZ);
        if ((rc = ioctl(sock, SIOCGIFINDEX, &ifr)))
                goto error;

        *if_index = ifr.ifr_ifindex;

        if ((rc = ioctl(sock, SIOCGIFHWADDR, &ifr)))
                goto error;

        rte_memcpy(eth_addr, ifr.ifr_hwaddr.sa_data, RTE_ETHER_ADDR_LEN);

        close(sock);
        return 0;

error:
        close(sock);
	MAIO_LOG(ERR, "%s: Failed with %d\n", ifr.ifr_name, rc);
        return -1;
}

static inline int setup_maio_matrix(struct pmd_internals *internals)
{
	int mtrx_proc, len, i, k;
	struct user_matrix *matrix;
	char write_buffer[WRITE_BUFF_LEN] = {0};

	matrix = rte_zmalloc_socket(NULL, sizeof(struct user_matrix) + DATA_MTRX_SZ,
						RTE_CACHE_LINE_SIZE, rte_socket_id());
	if ( ! matrix) {
		MAIO_LOG(ERR, "Failed to init internals\n");
		return -EINVAL;
	}

	if ((mtrx_proc = open(MTRX_PROC_NAME, O_RDWR)) < 0) {
		MAIO_LOG(ERR, "Failed to init internals %d\n", __LINE__);
		return -ENODEV;
	}

	len  = snprintf(write_buffer, WRITE_BUFF_LEN, "%llx %lu %d\n", (unsigned long long)matrix,
							sizeof(struct user_matrix) + DATA_MTRX_SZ,
							internals->if_index);
	//TODO: Set to actual num_avail_cpus.
	MAIO_LOG(ERR, ">>> seting user_matrix info @ %p\n", &matrix->info);
	matrix->rx_step = 0;
	matrix->info.nr_rx_rings = ETH_MAIO_DFLT_NUM_RINGS;
	matrix->info.nr_tx_rings = ETH_MAIO_DFLT_NUM_RINGS;
	matrix->info.nr_rx_sz = ETH_MAIO_DFLT_NUM_DESCS;
	matrix->info.nr_tx_sz = ETH_MAIO_DFLT_NUM_DESCS;

	for (i = 0, k = 0; i < NUM_MAX_RINGS; i++) {
		matrix->rings[i].rx.consumer = 0;
		matrix->rings[i].tx.consumer = 0;

		matrix->rings[i].rx.ring = matrix->info.rx_rings[i] =
					&matrix->base[ k++ * (ETH_MAIO_DFLT_NUM_DESCS)];
		matrix->rings[i].tx.ring = matrix->info.tx_rings[i] =
				&matrix->base[ k++ * (ETH_MAIO_DFLT_NUM_DESCS)];
		ASSERT((unsigned long)&matrix->rings[i].tx.ring[ETH_MAIO_DFLT_NUM_DESCS -1] < (unsigned long)&matrix->base[DATA_MTRX_SZ]);

		MAIO_LOG(ERR, "[%d]RX %p, TX %p\n",i, matrix->rings[i].rx.ring, matrix->rings[i].tx.ring);
	}

	len = write(mtrx_proc, write_buffer, len);

	MAIO_LOG(ERR, ">>> Sent %s\n", write_buffer);
	internals->napi_burst_tx	= eth_maio_napi_wrapper;
	internals->matrix		= matrix;
#if 0
	//rte_malloc_dump_stats(stdout, NULL);
	rte_memzone_dump(stdout);
	//rte_malloc_dump_heaps(stdout);
#endif

	close(mtrx_proc);
	return 0;
}

static inline struct rte_eth_dev *maio_init_internals(struct rte_vdev_device *dev, struct in_params *in_params)
{
	int ret;
	struct pmd_internals *internals;
	struct rte_eth_dev *eth_dev = rte_eth_vdev_allocate(dev, sizeof(*internals));

    static_dev = eth_dev;
	internals = eth_dev->data->dev_private;
        if (eth_dev == NULL || internals == NULL) {
                MAIO_LOG(ERR, "Failed to init internals\n");
                return NULL;
	}

	strlcpy(internals->if_name, in_params->if_name, IFNAMSIZ);
	internals->q_cnt = (in_params->q_cnt >= ETH_MAIO_MIN_NUM_RINGS &&
				in_params->q_cnt <= ETH_MAIO_MAX_NUM_RINGS)
				? in_params->q_cnt : ETH_MAIO_DFLT_NUM_RINGS;

	/* Q Len must be pow2 */
	in_params->q_len = (1 << rte_fls_u32(in_params->q_len));

	internals->q_len = (in_params->q_len >= ETH_MAIO_MIN_NUM_DESCS &&
				in_params->q_len <= ETH_MAIO_MAX_NUM_DESCS)
				? in_params->q_len : ETH_MAIO_DFLT_NUM_DESCS;

	ret = get_iface_info(internals->if_name, &internals->eth_addr, &internals->if_index);
        if (ret) {
                MAIO_LOG(ERR, "Failed to init internals [ignore leak]\n");
                return NULL;
	}

	ret = setup_maio_matrix(internals);
        if (ret) {
                MAIO_LOG(ERR, "Failed to init MATRIX [ignore leak]\n");
                return NULL;
	}

	MAIO_LOG(ERR, "Set %s q_cnt %d q_len %d\n", internals->if_name, internals->q_cnt, internals->q_len);
        eth_dev->data->dev_private = internals;
        eth_dev->data->dev_link = pmd_link;
        eth_dev->data->mac_addrs = &internals->eth_addr;
        eth_dev->dev_ops = &ops;
        eth_dev->rx_pkt_burst = eth_maio_rx;
        eth_dev->tx_pkt_burst = eth_maio_tx;
        /* Let rte_eth_dev_close() release the port resources. */
        eth_dev->data->dev_flags |= RTE_ETH_DEV_CLOSE_REMOVE;

	return eth_dev;
}

/** parse integer from integer argument */
static int parse_integer_arg(const char *key __rte_unused,
					const char *value, void *extra_args)
{
	int *i = (int *)extra_args;
	char *end;

	*i = strtoul(value, &end, 10);

	return 0;
}

/** parse name argument */
static int parse_name_arg(const char *key __rte_unused,
				const char *value, void *extra_args)
{
	char *name = extra_args;

	if (strnlen(value, IFNAMSIZ) > IFNAMSIZ - 1) {
		MAIO_LOG(ERR, "Invalid name %s, should be less than %u bytes.\n",
			   value, IFNAMSIZ);
		return -EINVAL;
	}

	strlcpy(name, value, IFNAMSIZ);

	return 0;
}

static inline int parse_parameters(struct rte_kvargs *kvlist, struct in_params *params)
{
	int ret;

	ret = rte_kvargs_process(kvlist, ETH_MAIO_IFACE_ARG,
				 &parse_name_arg, params->if_name);
	if (ret < 0)
		goto free_kvlist;

	ret = rte_kvargs_process(kvlist, ETH_MAIO_QUEUE_COUNT_ARG,
				 &parse_integer_arg, &params->q_cnt);
	if (ret < 0)
		goto free_kvlist;

	ret = rte_kvargs_process(kvlist, ETH_MAIO_QUEUE_LEN_ARG,
				 &parse_integer_arg, &params->q_len);
	if (ret < 0)
		goto free_kvlist;

	ret = rte_kvargs_process(kvlist, ETH_MAIO_ZC_TX_ARG,
				 &parse_integer_arg, &params->zc);
	if (ret < 0)
		goto free_kvlist;

	MAIO_LOG(ERR, "Got %s : %d\n", params->if_name, params->zc);
free_kvlist:
	rte_kvargs_free(kvlist);
	return ret;
}

/*TODO: FiXME
	1. Init.
	2. Create a struct for params
*/
static int rte_pmd_maio_probe(struct rte_vdev_device *dev)
{
	struct in_params in_params = {""};
	struct rte_kvargs *kvlist;
	struct rte_eth_dev *eth_dev = NULL;
	const char *name;
	static int memory_ready;
	char buffer[128];

	log_fd = open("/var/log/maio_log.txt", O_WRONLY | O_APPEND | O_CREAT, 0644);
	if (log_fd > 0) {
	    int bytes = snprintf(buffer, 128, "Hello World!!! %s\n", __DATE__);
	    write(log_fd, buffer, bytes);
	} else {
	    MAIO_LOG(ERR,"FAiled to open log_fd\n");
	}

	ASSERT(sizeof(struct io_md) <= 64);
	//ASSERT(sizeof(struct user_shadow) == 320);

	if (!trace_fd) {
		trace_fd = open(trace_marker, O_WRONLY);
		if (trace_fd < 0) {
			trace_fd = open(trace_marker_alt, O_WRONLY);
		}
		if (trace_fd > 0) {
			MAIO_LOG(ERR, "trace_fd %d\n", trace_fd);
		}
	}

        MAIO_LOG(ERR, "Initializing MAIO PMD for %s [%s]\n", rte_vdev_device_name(dev), __DATE__);

        name = rte_vdev_device_name(dev);
        if (rte_eal_process_type() == RTE_PROC_SECONDARY) {
		MAIO_LOG(ERR, "Failed to probe %s\n", name);
		return -EINVAL;
        }

        kvlist = rte_kvargs_parse(rte_vdev_device_args(dev), valid_arguments);
        if (kvlist == NULL) {
                MAIO_LOG(ERR, "Invalid kvargs key\n");
                return -EINVAL;
        }

        if (dev->device.numa_node == SOCKET_ID_ANY)
                dev->device.numa_node = rte_socket_id();

        if (parse_parameters(kvlist, &in_params) < 0) {
                MAIO_LOG(ERR, "Invalid kvargs value\n");
                return -EINVAL;
        }

	if (in_params.zc) {
                MAIO_LOG(ERR, "ZC TX set.\n");
		zc_tx_set = 1;
	}

        if (strlen(in_params.if_name) == 0) {
                MAIO_LOG(ERR, "Network interface must be specified\n");
                return -EINVAL;
        }

	/* map hugepages to MAIO */
	if (!memory_ready)
		rte_memseg_list_walk(prep_map_mem, 0);
	memory_ready = 1;

        eth_dev = maio_init_internals(dev, &in_params);
        if (eth_dev == NULL) {
                MAIO_LOG(ERR, "Failed to init internals\n");
                return -1;
        }

        rte_eth_dev_probing_finish(eth_dev);
        return 0;
}

static int rte_pmd_maio_remove(struct rte_vdev_device *dev)
{
        struct rte_eth_dev *eth_dev __rte_unused = NULL;

        MAIO_LOG(ERR, "Removing MAIO ethdev on numa socket %u\n",
                rte_socket_id());

        if (dev == NULL)
                return -1;
#if 0
        /* find the ethdev entry */
        eth_dev = rte_eth_dev_allocated(rte_vdev_device_name(dev));
        if (eth_dev == NULL)
                return 0;

        eth_dev_close(eth_dev);
        rte_eth_dev_release_port(eth_dev);
#endif

        return 0;
}

static struct rte_vdev_driver pmd_maio_drv = {
        .probe = rte_pmd_maio_probe,
        .remove = rte_pmd_maio_remove,
};

RTE_PMD_REGISTER_VDEV(net_maio, pmd_maio_drv);
RTE_PMD_REGISTER_PARAM_STRING(net_maio,
                              "iface=<string> "
                              "queue_count=<uint> "
                              "queue_len=<uint> "
				"zc=<uint>");

RTE_INIT(maio_init_log)
{
        maio_logtype = rte_log_register("pmd.net.maio");
        if (maio_logtype >= 0)
                rte_log_set_level(maio_logtype, RTE_LOG_NOTICE);
}

