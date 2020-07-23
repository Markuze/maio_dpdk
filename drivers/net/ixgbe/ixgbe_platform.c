// ixgbe_platform.c
// platform-specific functions;

#include <rte_ethdev_pci.h>

#include "base/ixgbe_type.h"
#include "base/ixgbe_phy.h"
#include "base/ixgbe_common.h"
#include "ixgbe_ethdev.h"
#include "ixgbe_bypass_defines.h"

void ixgbe_platform_laser_setup(struct ixgbe_hw *hw);

void ixgbe_platform_setup(struct ixgbe_hw *hw);

// platform specific SFP config;
int
ixgbe_platform_sfp_setup(struct ixgbe_hw *hw, u8 *vendor, u8 oui[3], u8 *partnum)
{
	(void)oui; (void)partnum;
	// increase settle time by another 100msec;
	// this fixes the 1G->10G->1G change issue;

	hw->phy.settle = 100;

	// metanoia vDSL needs a lot longer to boot;

	if( !strcmp((char *)vendor, "METANOIA"))
		hw->phy.settle = 2000;

	return 0;
}

STATIC s32 ixgbe_gpio_get_value(struct ixgbe_hw *hw, const char *pin_name)
{
	FILE *fp;
	char path[64];
	char buf[4] = {0};

	struct rte_eth_dev *eth_dev = (struct rte_eth_dev *)hw->back;
	struct rte_pci_device *pci_dev = RTE_ETH_DEV_TO_PCI(eth_dev);

	snprintf(path, 64, "/sys/devices/platform/vc/%s/%s",
		pci_dev->addr.function ? "sfp1" : "sfp2", pin_name);

	fp = fopen(path, "r");
	if (!fp) {
		return -EIO;
	}
	fread(buf, sizeof(buf) - 1, 1, fp);
	fclose(fp);

	return strtol(buf, NULL, 10);
}
STATIC s32 ixgbe_gpio_set_value(struct ixgbe_hw *hw, const char *pin_name, u32 val)
{
	FILE *fp;
	char path[64];

	struct rte_eth_dev *eth_dev = (struct rte_eth_dev *)hw->back;
	struct rte_pci_device *pci_dev = RTE_ETH_DEV_TO_PCI(eth_dev);

	snprintf(path, 64, "/sys/devices/platform/vc/%s/%s",
		pci_dev->addr.function ? "sfp1" : "sfp2", pin_name);

	fp = fopen(path, "w");
	if (!fp) {
		return -EIO;
	}

	fprintf(fp, "%d", val);
	fclose(fp);

	return 0;
}

// enable sfp laser;

STATIC s32 ixgbe_vc6x0_enable_tx_laser(struct ixgbe_hw *hw)
{
	int ret;

	if(hw->bus.lan_id > 1)
		return(IXGBE_ERR_PARAM);
	// enable laser if SFP present;
	// mandatory wait for light on;

	ret = ixgbe_gpio_get_value(hw, "present");
	if (ret < 0)
		return ret;
	if (ret != 0)
		return IXGBE_ERR_SFP_NOT_PRESENT;
	ixgbe_gpio_set_value(hw, "txdisable", 0);
	msec_delay(100);

	// check for laser fault;
	// return EIO for laser fault;

	ret = ixgbe_gpio_get_value(hw, "txfault");
	if (ret < 0)
		return ret;
	if (ret == 1) {
		PMD_DRV_LOG(ERR, "sfp laser/tx fault");
		ret = IXGBE_ERR_SFP_FAILED;
	}
	return ret;
}

// disable sfp laser;

STATIC s32 ixgbe_vc6x0_disable_tx_laser(struct ixgbe_hw *hw)
{
	if (hw->bus.lan_id > 1)
		return(IXGBE_ERR_PARAM);
	// disable laser;
	// mandatory wait for light off;

	ixgbe_gpio_set_value(hw, "txdisable", 1);
	usec_delay(100);

	return 0;
}

// flap sfp laser;

STATIC s32 ixgbe_vc6x0_flap_tx_laser(struct ixgbe_hw *hw)
{
	int ret = 0;

	if (hw->mac.autotry_restart) {
		ixgbe_vc6x0_disable_tx_laser(hw);
		ret = ixgbe_vc6x0_enable_tx_laser(hw);
		if (ret == 0)
			hw->mac.autotry_restart = false;
	}
	return(ret);
}

// sfp event handling;
// sample sfp presence signal and shift into event pipe;
// encoding is pipe states;

STATIC s32 ixgbe_vc6x0_sfp_event(struct ixgbe_hw *hw)
{
	u8 pipe, los;
	s32 event, ret;

	if(hw->bus.lan_id > 1)
		return(IXGBE_ERR_PARAM);

	// sfp presence detection;

	pipe = (hw->phy.sfp_event_pipe & 0x15) << 1;

	ret = ixgbe_gpio_get_value(hw, "present");
	if(ret < 0)
		return ret;
	if(ret == 0)
		pipe |= 1;
	event = pipe & 3;

	// if present, check tx fault and LOS;

	if(event == IXGBE_SFP_PRESENT) {
		ret = ixgbe_gpio_get_value(hw, "txfault");
		if(ret < 0)
			return ret;
		pipe |= (ret << 2);
		if((pipe & 0x0c) == 0x04)
			return(IXGBE_SFP_TXFAULT);

		ret = ixgbe_gpio_get_value(hw, "rxlos");
		if(ret < 0)
			return ret;
		pipe |= (ret << 4);
		los = pipe & 0x30;
		if(los == 0x10)
			event = IXGBE_SFP_LOS;
		else if(los == 0x20)
			event = IXGBE_SFP_DOS;
	} else {
		pipe |= 0x3c;
	}

	hw->phy.sfp_event_pipe = pipe;
	return event;
}

// set SFP link-speed LEDs;

STATIC s32 ixgbe_vc6x0_sfp_led(struct ixgbe_hw *hw, u32 speed)
{
	int green, amber;

	if(hw->bus.lan_id > 1)
		return(IXGBE_ERR_PARAM);

	// green = 10G, amber = 1G;

	green = amber = 0;
	switch(speed) {
	case IXGBE_LINK_SPEED_10GB_FULL:
		green = 1;
		break;
	case IXGBE_LINK_SPEED_1GB_FULL:
		amber = 1;
		break;
	}
	ixgbe_gpio_set_value(hw, "green", !green);
	ixgbe_gpio_set_value(hw, "amber", !amber);

	return 0;
}

STATIC s32 ixgbe_vc6x5_sfp_led(struct ixgbe_hw *hw, u32 speed)
{
	int color;
	if(hw->bus.lan_id > 1)
		return(IXGBE_ERR_PARAM);

	color = 0;
	switch(speed) {
	case IXGBE_LINK_SPEED_10GB_FULL:
		color = 0;
		break;
	case IXGBE_LINK_SPEED_1GB_FULL:
		color = 1;
		break;
	default:
		return 0;
	}

    ixgbe_gpio_set_value(hw, "color", color);

    return 0;
}

// velocloud laser setup;

STATIC void ixgbe_vc_laser_setup(struct ixgbe_hw *hw)
{
	FILE *fp;
	char buf[8];
	fp = fopen("/sys/devices/platform/vc/board", "r");
	if (fp == NULL) {
		PMD_DRV_LOG(ERR, "Cannot open " \
                        "/sys/devices/platform/vc/board " \
                        "for board type");
		return;
	}
	fread(buf, sizeof(buf), 1, fp);
	fclose(fp);
	if (strncmp("edge620", buf, 7) == 0) { goto config; }
	else if (strncmp("edge640", buf, 7) == 0) { goto config; }
	else if (strncmp("edge680", buf, 7) == 0) { goto config; }
	else if (strncmp("edge625", buf, 7) == 0) { goto config; }
	else if (strncmp("edge645", buf, 7) == 0) { goto config; }
	else if (strncmp("edge685", buf, 7) == 0) { goto config; }
	else { return; }
config:
	hw->mac.ops.disable_tx_laser = ixgbe_vc6x0_disable_tx_laser;
	hw->mac.ops.enable_tx_laser = ixgbe_vc6x0_enable_tx_laser;
	hw->mac.ops.flap_tx_laser = ixgbe_vc6x0_flap_tx_laser;
}

// setup sfp event handler;

STATIC void ixgbe_vc_setup(struct ixgbe_hw *hw)
{
	FILE *fp;
	char buf[8];

	fp = fopen("/sys/devices/platform/vc/board", "r");
	if (fp == NULL) {
		PMD_DRV_LOG(ERR, "Cannot open " \
			"/sys/devices/platform/vc/board " \
			"for board type");
		return;
	}
	fread(buf, sizeof(buf), 1, fp);
	fclose(fp);

	if (strncmp("edge620", buf, 7) == 0) {
		if(hw->device_id == IXGBE_DEV_ID_X550EM_A_SFP_N) {
			hw->phy.speeds_sku |= IXGBE_LINK_SPEED_2_5GB_FULL;
			hw->phy.speeds_sku |= IXGBE_LINK_SPEED_5GB_FULL;
			hw->phy.speeds_sku |= IXGBE_LINK_SPEED_10GB_FULL;
		}
	}
	if ((strncmp("edge640", buf, 7) == 0) ||
			(strncmp("edge680", buf, 7) == 0)) {
		if(hw->device_id == IXGBE_DEV_ID_X550EM_A_SFP_N) {
			hw->phy.speeds_sku |= IXGBE_LINK_SPEED_10_FULL;
			hw->phy.speeds_sku |= IXGBE_LINK_SPEED_100_FULL;
			hw->phy.ops.sfp_event = ixgbe_vc6x0_sfp_event;
			hw->phy.ops.link_led = ixgbe_vc6x0_sfp_led;
			hw->phy.sfp_present = 0;
			ixgbe_vc6x0_sfp_led(hw, IXGBE_LINK_SPEED_UNKNOWN);
		}
	}
	if ((strncmp("edge625", buf, 7) == 0) ||
			(strncmp("edge645", buf, 7) == 0) ||
			(strncmp("edge685", buf, 7) == 0)) {
		if(hw->device_id == IXGBE_DEV_ID_X550EM_A_SFP_N) {
			hw->phy.speeds_sku |= IXGBE_LINK_SPEED_10_FULL;
			hw->phy.speeds_sku |= IXGBE_LINK_SPEED_100_FULL;
			hw->phy.ops.sfp_event = ixgbe_vc6x0_sfp_event;
			hw->phy.ops.link_led = ixgbe_vc6x5_sfp_led;
			hw->phy.sfp_present = 0;
			ixgbe_vc6x0_sfp_led(hw, IXGBE_LINK_SPEED_UNKNOWN);
		}
	}
}

// platform specific sfp setup;

void ixgbe_platform_laser_setup(struct ixgbe_hw *hw)
{
	ixgbe_vc_laser_setup(hw);
}

// platform SFP detection;

STATIC s32 ixgbe_dummy_sfp_event(__rte_unused struct ixgbe_hw *hw)
{
	return IXGBE_SFP_NO_PLATFORM;
}

// setup sfp link led handler;

void ixgbe_platform_setup(struct ixgbe_hw *hw)
{
	hw->phy.ops.sfp_event = ixgbe_dummy_sfp_event;
	ixgbe_vc_setup(hw);
}

