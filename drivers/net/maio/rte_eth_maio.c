#include <unistd.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>

#include <sys/ioctl.h>
#include <linux/sockios.h>
#include <linux/if_ether.h>
#include <linux/if.h>

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
static int lwm_mark_trigger;

#define WRITE_BUFF_LEN	256

#define COOKIE "--"
#define MAIO_LOG(level, fmt, args...)                 \
	fprintf(stderr, "%s)"COOKIE fmt, __FUNCTION__, ##args);


#define ASSERT(exp)								\
		if (!(exp))							\
			rte_panic("%s:%d\tassert \"" #exp "\" failed\n",	\
						__FUNCTION__, __LINE__)		\

static const char *const valid_arguments[] = {
        ETH_MAIO_IFACE_ARG,
        ETH_MAIO_QUEUE_COUNT_ARG,
        NULL
};

static const struct rte_eth_link pmd_link = {
        .link_speed = ETH_SPEED_NUM_10G,
        .link_duplex = ETH_LINK_FULL_DUPLEX,
        .link_status = ETH_LINK_DOWN,
        .link_autoneg = ETH_LINK_AUTONEG
};

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
	MAIO_LOG(ERR, "%d\n", __LINE__);
	maio_set_state("0");
        dev->data->dev_link.link_status = ETH_LINK_DOWN;
}

static int eth_dev_start(struct rte_eth_dev *dev)
{
	MAIO_LOG(ERR, "%d\n", __LINE__);
	maio_set_state("1");
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
	MAIO_LOG(ERR, "%d\n", __LINE__);
        return 0;
}

/* TODO: FIXME**/
static int eth_dev_info(struct rte_eth_dev *dev, struct rte_eth_dev_info *dev_info)
{
	struct pmd_internals *internals = dev->data->dev_private;

	MAIO_LOG(ERR, "%d\n", __LINE__);

	dev_info->if_index = internals->if_index;
	dev_info->max_mac_addrs = 1;
	dev_info->max_rx_pktlen = ETH_FRAME_LEN;
	dev_info->max_rx_queues = 1;
	dev_info->max_tx_queues = 1;

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

	MAIO_LOG(ERR, "%d\n", __LINE__);

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

	MAIO_LOG(ERR, "%d\n", __LINE__);

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

	MAIO_LOG(ERR, "%d\n", __LINE__);

	return eth_dev_change_flags(internals->if_name, IFF_PROMISC, ~0);
}

static int eth_dev_promiscuous_disable(struct rte_eth_dev *dev)
{
	struct pmd_internals *internals = dev->data->dev_private;

	MAIO_LOG(ERR, "%d\n", __LINE__);

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

	static int memory_ready;

	if (memory_ready)
		return 0;

	memory_ready = 1;

	len = min(ETH_MAIO_NUM_INIT_BUFFS, mb_pool->populated_size >> 1);

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
#if 1
	/* TODO: Figure out why not main msl?!?! MAPPING MBUF MEMORY */
	maio_map_memory((void *)get_base_addr(mb_pool), DIV_ROUND_UP_HP((mb_pool->populated_size * ETH_MAIO_MBUF_STRIDE)));
#endif
	for (i = 0; i < len; i++) {
#if 0
		if ((unsigned long long)mbufs[i] & ETH_MAIO_MBUF_STRIDE) {
			continue;
		}
#endif
		pages->bufs[i] = mbufs[i];
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
	pages->headroom = (uint64_t)mbufs[0]->buf_addr & ~ETH_MAIO_STRIDE_MASK;
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
	MAIO_LOG(ERR, "HERE %d\n", __LINE__);
	maio_map_mbuf(mb_pool);
	dev->data->rx_queues[rx_queue_id] = internals->matrix;

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
	struct pmd_internals *internals  = dev->data->dev_private;
	dev->data->tx_queues[tx_queue_id] = internals->matrix;

	if (!tx_proc) {
		if ((tx_proc = open(TX_PROC_NAME, O_RDWR)) < 0) {
			MAIO_LOG(ERR, "Failed to init internals %d\n", __LINE__);
			return -ENODEV;
		}
	}

	internals->matrix->tx[tx_queue_id].fd = tx_proc;
	internals->matrix->tx[tx_queue_id].idx = internals->if_index;
	MAIO_LOG(ERR, "%s %d\n","HERE" ,__LINE__);

	return 0;
}

static void eth_queue_release(void *q __rte_unused)
{
	MAIO_LOG(ERR, "%d\n", __LINE__);
}

static int eth_link_update(struct rte_eth_dev *dev __rte_unused,
				int wait_to_complete __rte_unused)
{
	MAIO_LOG(ERR, "%d\n", __LINE__);
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
	char write_buffer[WRITE_BUFF_LEN];
	int len, cur = 0;

	eth 	= rte_pktmbuf_mtod(mbuf, struct rte_ether_hdr *);
	ip	= (struct rte_ipv4_hdr *)&eth[1];

	//len = snprintf(&write_buffer[cur], WRITE_BUFF_LEN - cur,"%s\n", str);
	//cur += len;
	len = snprintf(&write_buffer[cur], WRITE_BUFF_LEN - cur, "%s:IN type: 0x%x: %p \n:D_MAC address: %02X:%02X:%02X:%02X:%02X:%02X\n",
			str,
			rte_cpu_to_be_16(eth->ether_type),
			eth,
			eth->d_addr.addr_bytes[0],
			eth->d_addr.addr_bytes[1],
			eth->d_addr.addr_bytes[2],
			eth->d_addr.addr_bytes[3],
			eth->d_addr.addr_bytes[4],
			eth->d_addr.addr_bytes[5]);
	cur += len;
	len = snprintf(&write_buffer[cur], WRITE_BUFF_LEN - cur, "%s:S_MAC address: %02X:%02X:%02X:%02X:%02X:%02X\n",
			str,
			eth->s_addr.addr_bytes[0],
			eth->s_addr.addr_bytes[1],
			eth->s_addr.addr_bytes[2],
			eth->s_addr.addr_bytes[3],
			eth->s_addr.addr_bytes[4],
			eth->s_addr.addr_bytes[5]);
	cur += len;
	len = snprintf(&write_buffer[cur], WRITE_BUFF_LEN - cur,"%s:SIP: %0x DIP: %0x\n",
			str,
			ip->src_addr, ip->dst_addr);
	printf("%s\n", write_buffer);
}

#define SHOW_IO(...)
#define advance_ring(r)			(r)->ring[(r)->consumer++ & ETH_MAIO_DFLT_DESC_MASK] = 0
#define post_ring_entry(r, p)		(r)->ring[(r)->consumer++ & ETH_MAIO_DFLT_DESC_MASK] = (unsigned long)p
#define ring_entry(r)			(r)->ring[(r)->consumer & ETH_MAIO_DFLT_DESC_MASK]

	//((t)((char *)(m)->buf_addr + (m)->data_off + (o)))
static inline struct rte_mbuf *maio_addr2mbuf(uint64_t addr)
{
	struct rte_mbuf *mbuf = (struct rte_mbuf *)((addr & ETH_MAIO_STRIDE_MASK) + ALLIGNED_MBUF_OFFSET);

	ASSERT(addr > (uint64_t)mbuf->buf_addr);
	mbuf->data_off = addr - (uint64_t)mbuf->buf_addr;
	return mbuf;
}

static inline int addr_wm_signal(uint64_t addr)
{
	struct rte_mbuf *mbuf;

	if (addr == MAIO_POISON) {
		lwm_mark_trigger = 1;
		return 1;
	}

	//page aligned address is a refill packet
	if (addr & ETH_MAIO_STRIDE_MASK) {
		mbuf = (struct rte_mbuf *)((addr & ETH_MAIO_STRIDE_MASK) + ALLIGNED_MBUF_OFFSET);
		/*TODO: Add rte_pktmbuf_free optimization */
		rte_pktmbuf_free(mbuf);
		return 1;
	}

	return 0;
}

static inline struct rte_mbuf **poll_maio_ring(struct user_ring *ring,
						struct rte_mbuf **bufs,
						uint16_t *cnt, uint32_t *bytes, uint16_t nb_pkts)
{
	int i = 0;
	uint32_t byte_cnt = 0;

	while (ring_entry(ring))  {
		struct rte_mbuf *mbuf;
		struct io_md *md;
		uint64_t addr = ring_entry(ring);

		if (addr_wm_signal(addr))
			continue;
		mbuf 	= maio_addr2mbuf(addr);
		//printf("Received[%ld] 0x%lx - mbuf %lx\n", ring->consumer, addr, mbuf);
		//printf("mbuf %p: data %p offset %d\n", mbuf, mbuf->buf_addr, mbuf->data_off);
		md 	= rte_pktmbuf_mtod(mbuf, struct io_md *);
		md--;
		advance_ring(ring);
		ASSERT(mbuf->pool == maio_mb_pool);
		ASSERT(md->poison == MAIO_POISON);
		rte_pktmbuf_pkt_len(mbuf) = md->len;
		rte_pktmbuf_data_len(mbuf) = md->len;

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

//RX HERE
static uint16_t eth_maio_rx(void *queue,
				struct rte_mbuf **bufs,
				uint16_t nb_pkts)
{
	int i;
	uint32_t bytes;
	uint16_t cnt = 0;
	uint16_t rcv = 0;
	struct user_matrix *matrix = queue;
	struct pmd_stats *stats = &matrix->stats;

	for (i = 0; i < NUM_MAX_RINGS; i++) {
		bufs = poll_maio_ring(&matrix->rx[i], bufs, &cnt, &bytes, nb_pkts);
		nb_pkts -= cnt;
		rcv 	+= cnt;

		stats->rx_queue[i].pkts += cnt;
		stats->rx_queue[i].bytes += bytes;

		if (!nb_pkts)
			break;
	}
	return rcv;
}

static inline struct io_md *get_mbuf(struct rte_mbuf *mbuf)
{
	struct io_md *md = rte_pktmbuf_mtod(mbuf, struct io_md *);
#if 0
	static int i;
	if (i) {
		struct rte_mbuf *new = rte_pktmbuf_alloc(maio_mb_pool);
		struct io_md *new_md;

		if (!new)
			return md;

		new_md = rte_pktmbuf_mtod(new, struct io_md *);

		//printf("Copying mbuf %p\n", mbuf);
		memcpy(new_md, md, rte_pktmbuf_data_len(mbuf));
		md = new_md;
	}

	i ^= 1;
#endif
	return md;
}

static inline int post_maio_ring(struct tx_user_ring *ring,
					struct rte_mbuf **bufs,
					uint16_t nb_pkts, struct q_stat *tx_queue)
{
	int i = nb_pkts;
	uint32_t bytes = 0 ;

	while (nb_pkts--)  {
		struct rte_mbuf *mbuf = *bufs;
		struct io_md *md;

		if (ring_entry(ring)) {
			i = i - nb_pkts;
			goto stats;
		}

		SHOW_IO(mbuf, "TX");
		ASSERT(mbuf->pool == maio_mb_pool);
		//md = rte_pktmbuf_mtod(mbuf, struct io_md *);
		md = get_mbuf(mbuf);
		//printf("mbuf %p: data %p offset %d len %d\n", md, mbuf->buf_addr, mbuf->data_off, rte_pktmbuf_data_len(mbuf));
		md--;
		md->poison = MAIO_POISON;
		md->len = rte_pktmbuf_data_len(mbuf);

		post_ring_entry(ring, ++md);
		bufs++;

		bytes += md->len;
	}
stats:
	tx_queue->pkts	+= i;
	tx_queue->bytes += bytes;

	return i;
}

#define REFILL_NUM	32
static uint16_t eth_maio_tx(void *queue,
				struct rte_mbuf **bufs,
				uint16_t nb_pkts)
{
	struct user_matrix *matrix = queue;
	struct pmd_stats *stats = &matrix->stats;
	char write_buffer[WRITE_BUFF_LEN] = {0};
	int len, rc = nb_pkts;

	if (lwm_mark_trigger) {
		struct rte_mbuf *mbufs[REFILL_NUM];
		if (rte_pktmbuf_alloc_bulk(maio_mb_pool, mbufs, REFILL_NUM)) {
			MAIO_LOG(ERR, "Failed to get enough buffers on LWM trigger!.\n");
			return -ENOMEM;
		}
		rc = post_maio_ring(&matrix->tx[0], mbufs, REFILL_NUM, NULL);
		lwm_mark_trigger = 0;
	}
	/* Fill Ring 0 -- Only Ring 0 is used today */
	rc = post_maio_ring(&matrix->tx[0], bufs, nb_pkts, &stats->tx_queue[0]);
	/* Ring DoorBell -- SysCall */
	/*,rte_lcore_id()*/
	len = snprintf(write_buffer, WRITE_BUFF_LEN, "%d\n", matrix->tx[0].idx);
	len = write(matrix->tx[0].fd, write_buffer, len);
	//printf("Posted %s %d/%d packets on lcore %d [%d] \n", (rc == nb_pkts) ? "all":"ERROR", rc, nb_pkts, rte_lcore_id(), len);
	return rc;
}

static inline int get_iface_info(const char *if_name, struct rte_ether_addr *eth_addr, int *if_index)
{
	int line = __LINE__;
	int rc = 0;
        struct ifreq ifr;
        int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);

	line = __LINE__;
        if (sock < 0)
                return -1;

	line = __LINE__;
        strlcpy(ifr.ifr_name, if_name, IFNAMSIZ);
        if ((rc = ioctl(sock, SIOCGIFINDEX, &ifr)))
                goto error;

        *if_index = ifr.ifr_ifindex;

	line = __LINE__;
        if ((rc = ioctl(sock, SIOCGIFHWADDR, &ifr)))
                goto error;

        rte_memcpy(eth_addr, ifr.ifr_hwaddr.sa_data, RTE_ETHER_ADDR_LEN);

        close(sock);
        return 0;

error:
        close(sock);
	MAIO_LOG(ERR, "%s: Failed on %d with %d\n", ifr.ifr_name, line, rc);
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
	matrix->info.nr_rx_rings = 8;
	matrix->info.nr_tx_rings = 8;
	matrix->info.nr_rx_sz = ETH_MAIO_DFLT_NUM_DESCS;
	matrix->info.nr_tx_sz = ETH_MAIO_DFLT_NUM_DESCS;

	for (i = 0, k = 0; i < NUM_MAX_RINGS; i++) {
		matrix->rx[i].ring = matrix->info.rx_rings[i] =
				&matrix->base[ k++ * (ETH_MAIO_DFLT_NUM_DESCS)];
		matrix->tx[i].ring = matrix->info.tx_rings[i] =
				&matrix->base[ k++ * (ETH_MAIO_DFLT_NUM_DESCS)];
		ASSERT((unsigned long)&matrix->tx[i].ring[ETH_MAIO_DFLT_NUM_DESCS -1] < (unsigned long)&matrix->base[DATA_MTRX_SZ]);

		MAIO_LOG(ERR, "[%d]RX %p, TX %p\n",i, matrix->rx[i].ring, matrix->tx[i].ring);
	}

	len = write(mtrx_proc, write_buffer, len);

	MAIO_LOG(ERR, ">>> Sent %s\n", write_buffer);
	internals->matrix = matrix;
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

	internals = eth_dev->data->dev_private;
        if (eth_dev == NULL || internals == NULL) {
                MAIO_LOG(ERR, "Failed to init internals\n");
                return NULL;
	}

	strlcpy(internals->if_name, in_params->if_name, IFNAMSIZ);
	internals->q_cnt = in_params->q_cnt;

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

	*i = strtol(value, &end, 10);
	if (*i < 0) {
		MAIO_LOG(ERR, "Argument has to be positive.\n");
		return -EINVAL;
	}

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

	MAIO_LOG(ERR, "Got %s : %d\n", params->if_name, params->q_cnt);
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
	struct in_params in_params = {0};
        struct rte_kvargs *kvlist;
        struct rte_eth_dev *eth_dev = NULL;
        const char *name;

	printf("Hello vdev :)[%s]:%s:\n", __FUNCTION__, __TIME__);
        MAIO_LOG(ERR, "Initializing pmd_maio for %s\n", rte_vdev_device_name(dev));

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

        if (strlen(in_params.if_name) == 0) {
                MAIO_LOG(ERR, "Network interface must be specified\n");
                return -EINVAL;
        }

	/* map hugepages to MAIO */
	rte_memseg_list_walk(prep_map_mem, 0);

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
                              "start_queue=<int> "
                              "queue_count=<int> ");

RTE_INIT(maio_init_log)
{
        maio_logtype = rte_log_register("pmd.net.maio");
        if (maio_logtype >= 0)
                rte_log_set_level(maio_logtype, RTE_LOG_NOTICE);
}

