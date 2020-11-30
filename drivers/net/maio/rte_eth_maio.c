#include <unistd.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>

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

static int maio_logtype;

#define MAIO_LOG(level, fmt, args...)                 \
        rte_log(RTE_LOG_ ## level, maio_logtype,      \
                "%s(): " fmt, __func__, ##args)

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

/* This function gets called when the current port gets stopped. */
static void eth_dev_stop(struct rte_eth_dev *dev)
{
	MAIO_LOG(INFO, "%d\n", __LINE__);
        dev->data->dev_link.link_status = ETH_LINK_DOWN;
}

static int eth_dev_start(struct rte_eth_dev *dev)
{
	MAIO_LOG(INFO, "%d\n", __LINE__);
	dev->data->dev_link.link_status = ETH_LINK_UP;

	return 0;
}

static void eth_dev_close(struct rte_eth_dev *dev)
{
	struct pmd_internals *internals __rte_unused = dev->data->dev_private;

	MAIO_LOG(INFO, "Closing MAIO ethdev on numa socket %u\n", rte_socket_id());
}

static int eth_dev_configure(struct rte_eth_dev *dev __rte_unused)
{
	MAIO_LOG(INFO, "%d\n", __LINE__);
        return 0;
}

/* TODO: FIXME**/
static int eth_dev_info(struct rte_eth_dev *dev, struct rte_eth_dev_info *dev_info)
{
	struct pmd_internals *internals = dev->data->dev_private;

	MAIO_LOG(INFO, "%d\n", __LINE__);

	dev_info->if_index = internals->if_index;
	dev_info->max_mac_addrs = 1;
	dev_info->max_rx_pktlen = ETH_FRAME_LEN;
	//dev_info->max_rx_queues = internals->queue_cnt;
	//dev_info->max_tx_queues = internals->queue_cnt;

	dev_info->min_mtu = RTE_ETHER_MIN_MTU;
	dev_info->max_mtu = ETH_MAX_MTU;

	dev_info->default_rxportconf.nb_queues = 1;
	dev_info->default_txportconf.nb_queues = 1;
	dev_info->default_rxportconf.ring_size = ETH_MAIO_DFLT_NUM_DESCS;
	dev_info->default_txportconf.ring_size = ETH_MAIO_DFLT_NUM_DESCS;

	return 0;
}

static int eth_dev_mtu_set(struct rte_eth_dev *dev, uint16_t mtu)
{
	struct pmd_internals *internals = dev->data->dev_private;
	struct ifreq ifr = { .ifr_mtu = mtu };
	int ret;
	int s;

	MAIO_LOG(INFO, "%d\n", __LINE__);

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

	MAIO_LOG(INFO, "%d\n", __LINE__);

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

	MAIO_LOG(INFO, "%d\n", __LINE__);

	return eth_dev_change_flags(internals->if_name, IFF_PROMISC, ~0);
}

static int eth_dev_promiscuous_disable(struct rte_eth_dev *dev)
{
	struct pmd_internals *internals = dev->data->dev_private;

	MAIO_LOG(INFO, "%d\n", __LINE__);

	return eth_dev_change_flags(internals->if_name, 0, ~IFF_PROMISC);
}

/* TODO: FIXME**/
static int eth_rx_queue_setup(struct rte_eth_dev *dev,
				uint16_t rx_queue_id __rte_unused,
				uint16_t nb_rx_desc __rte_unused,
				unsigned int socket_id __rte_unused,
				const struct rte_eth_rxconf *rx_conf __rte_unused,
				struct rte_mempool *mb_pool __rte_unused)
{
	struct pmd_internals *internals  __rte_unused = dev->data->dev_private;

	MAIO_LOG(INFO, "FIXME %d\n", __LINE__);

	return 0;
}

/* TODO: FIXME**/
static int eth_tx_queue_setup(struct rte_eth_dev *dev,
				uint16_t tx_queue_id __rte_unused,
				uint16_t nb_tx_desc __rte_unused,
				unsigned int socket_id __rte_unused,
				const struct rte_eth_txconf *tx_conf __rte_unused)
{
	struct pmd_internals *internals  __rte_unused = dev->data->dev_private;

	MAIO_LOG(INFO, "FIXME %d\n", __LINE__);

	return 0;
}

static void eth_queue_release(void *q __rte_unused)
{
	MAIO_LOG(INFO, "%d\n", __LINE__);
}

static int eth_link_update(struct rte_eth_dev *dev __rte_unused,
				int wait_to_complete __rte_unused)
{
	MAIO_LOG(INFO, "%d\n", __LINE__);
	return 0;
}

static int eth_stats_get(struct rte_eth_dev *dev, struct rte_eth_stats *stats __rte_unused)
{
	struct pmd_internals *internals  __rte_unused = dev->data->dev_private;

	MAIO_LOG(INFO, "FIXME %d\n", __LINE__);

	return 0;
}

static int eth_stats_reset(struct rte_eth_dev *dev)
{
	struct pmd_internals *internals __rte_unused = dev->data->dev_private;

	MAIO_LOG(INFO, "FIXME %d\n", __LINE__);

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

/*TODO: FiXME
	1. RX Func.
*/
static uint16_t eth_maio_rx(void *queue __rte_unused,
				struct rte_mbuf **bufs __rte_unused,
				uint16_t nb_pkts __rte_unused)
{
	return 0;
}

/*TODO: FiXME
	1. RX Func.
*/
static uint16_t eth_maio_tx(void *queue __rte_unused,
				struct rte_mbuf **bufs __rte_unused,
				uint16_t nb_pkts __rte_unused)
{
	return 0;
}

static inline int get_iface_info(const char *if_name,
               struct rte_ether_addr *eth_addr,
               int *if_index)
{
        struct ifreq ifr;
        int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);

        if (sock < 0)
                return -1;

        strlcpy(ifr.ifr_name, if_name, IFNAMSIZ);
        if (ioctl(sock, SIOCGIFINDEX, &ifr))
                goto error;

        *if_index = ifr.ifr_ifindex;

        if (ioctl(sock, SIOCGIFHWADDR, &ifr))
                goto error;

        rte_memcpy(eth_addr, ifr.ifr_hwaddr.sa_data, RTE_ETHER_ADDR_LEN);

        close(sock);
        return 0;

error:
        close(sock);
        return -1;
}


static inline int setup_maio_matrix(struct pmd_internals *internals)
{
	        internals->matrix = rte_zmalloc_socket(NULL, sizeof(struct user_matrix) + DATA_MTRX_SZ,
							RTE_CACHE_LINE_SIZE, rte_socket_id());
		if ( ! internals->matrix) {
			MAIO_LOG(ERR, "Failed to init internals\n");
			return -EINVAL;
		}
		/* TODO: Register META to Kernel */

		return 0;
}

static inline struct rte_eth_dev *maio_init_internals(struct rte_vdev_device *dev)
{
	int ret;
	struct pmd_internals *internals;
	struct rte_eth_dev *eth_dev = rte_eth_vdev_allocate(dev, sizeof(*internals));

	internals = eth_dev->data->dev_private;
        if (eth_dev == NULL || internals == NULL) {
                MAIO_LOG(ERR, "Failed to init internals\n");
                return NULL;
	}

/*
	ret = get_iface_info(if_name, &internals->eth_addr, &internals->if_index);
        if (ret) {
                MAIO_LOG(ERR, "Failed to init internals [ignore leak]\n");
                return NULL;
	}
*/
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

/*TODO: FiXME
	1. Init.
	2. Create a struct for params
*/
static int rte_pmd_maio_probe(struct rte_vdev_device *dev)
{
        struct rte_kvargs *kvlist;
        char if_name[IFNAMSIZ]  __rte_unused	= {'\0'};
	int qcnt		__rte_unused	= 0;
        struct rte_eth_dev *eth_dev  __rte_unused = NULL;
        const char *name __rte_unused;

	printf("Hello vdev :)[%s]\n", __FUNCTION__);
        MAIO_LOG(INFO, "Initializing pmd_maio for %s\n",
                rte_vdev_device_name(dev));
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

#if 0
        if (parse_parameters(kvlist, if_name, &qcnt) < 0) {
                MAIO_LOG(ERR, "Invalid kvargs value\n");
                return -EINVAL;
        }

        if (strlen(if_name) == 0) {
                MAIO_LOG(ERR, "Network interface must be specified\n");
                return -EINVAL;
        }
#endif
        eth_dev = maio_init_internals(dev);
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

        MAIO_LOG(INFO, "Removing MAIO ethdev on numa socket %u\n",
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

