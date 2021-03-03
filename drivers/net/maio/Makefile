
include $(RTE_SDK)/mk/rte.vars.mk

#
# library name
#
LIB = librte_pmd_maio.a

EXPORT_MAP := rte_pmd_maio_version.map

CFLAGS += -O3

CFLAGS += $(WERROR_FLAGS)
LDLIBS += -lrte_eal -lrte_mbuf -lrte_mempool -lrte_ring
LDLIBS += -lrte_ethdev -lrte_net -lrte_kvargs
LDLIBS += -lrte_bus_vdev

#
# all source are stored in SRCS-y
#
SRCS-$(CONFIG_RTE_LIBRTE_PMD_MAIO) += rte_eth_maio.c

include $(RTE_SDK)/mk/rte.lib.mk
