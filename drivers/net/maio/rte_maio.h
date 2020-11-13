#ifndef __RTE_MAIO__
#define __RTE_MAIO__

#define ETH_MAIO_IFACE_ARG		"iface"
#define ETH_MAIO_QUEUE_COUNT_ARG	"queue_count"

#define ETH_MAIO_DFLT_NUM_DESCS		512

struct pmd_internals {

	int if_index;
	char if_name[IFNAMSIZ];
};

#endif //__RTE_MAIO__
