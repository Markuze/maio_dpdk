// SPDX-License-Identifier: GPL-2.0
/*-
 * Copyright(c) 2010-2017 Intel Corporation. All rights reserved.
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/device.h>
#include <linux/module.h>
#include <linux/pci.h>
#include <linux/uio_driver.h>
#include <linux/io.h>
#include <linux/irq.h>
#include <linux/msi.h>
#include <linux/version.h>
#include <linux/slab.h>
#include <linux/gpio.h>
#if LINUX_VERSION_CODE < KERNEL_VERSION(4,4,0)
#include <linux/mdio-gpio.h>
#else
#include <linux/platform_data/mdio-gpio.h>
#endif
#include <linux/delay.h>
#include <linux/i2c.h>
#include <linux/cdev.h>
#include <misc/velocloud.h>

#include <rte_pci_dev_features.h>
#include <vc_ioctl.h>

#include "compat.h"

/**
 * A structure describing the private information for a uio device.
 */
struct rte_uio_pci_dev {
	struct uio_info info;
	struct pci_dev *pdev;
	enum rte_intr_mode mode;
	atomic_t refcnt;
};

static int wc_activate;
static char *intr_mode;
static enum rte_intr_mode igbuio_intr_mode_preferred = RTE_INTR_MODE_MSIX;


#ifndef NON_VELOCLOUD_KERNEL
extern struct dmi_system_id *vc_dmi;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,14,114)
extern struct mii_bus *vc_mdio_get(int index);
#else
extern struct mii_bus *vc_mdio_bus;
#endif //NON_VELOCLOUD_KERNEL

#define IGB_VC_SFP "sfp"        // sfp i2c driver name;


#define EDGE5X0_GPIO_PCA9557_30 70
#define EDGE5X0_GPIO_RST_SW_A (EDGE5X0_GPIO_PCA9557_30 + 2)
#define EDGE5X0_GPIO_RST_SW_B (EDGE5X0_GPIO_PCA9557_30 + 3)
#define EDGE5X0_GPIO_RST_1514 (EDGE5X0_GPIO_PCA9557_30 + 4)

#define IGB_VC_N_BUS_FUNC 4

#define WAN_MAX_DEVS            1
#define WAN_LINK_MAX_DEVS  2

static int igb_vc5x0_reset_gpio[IGB_VC_N_BUS_FUNC] = {
        EDGE5X0_GPIO_RST_SW_A,
        EDGE5X0_GPIO_RST_SW_B,
        EDGE5X0_GPIO_RST_1514,
        -1,
};

enum sfp_i2c_client {
        SFP_EEPROM = 0,
        SFP_DMI,
        N_SFP_CLIENT,
};

struct vc_wan_pci_addrs {
   u8 bus;
   u8 devfn;
};

struct vc_edge540 {
   atomic_t ref_count;
   struct vc_wan_pci_addrs *pci_addrs;
};

static struct vc_wan_pci_addrs pci_addr[WAN_LINK_MAX_DEVS] = {
                { 0, PCI_DEVFN(0x14, 2) },
                { 0, PCI_DEVFN(0x14, 3) },
};

static struct vc_edge540 vc_hw_edge540 = {
   .ref_count = { 0 },
   .pci_addrs = pci_addr,
};

static struct i2c_client *vc_client[N_SFP_CLIENT];

// sfp i2c data;
static unsigned short igb_vc_i2c_addrs[] = { 0x50, 0x51, I2C_CLIENT_END };

// detect i2c devices;
// called for each i2c device before probing, by the i2c core;
// device addresses are in struct i2c_driver.address_list;

static int
igb_vc_i2c_detect(struct i2c_client *client, struct i2c_board_info *info)
{
   struct i2c_adapter *adapter = client->adapter;

   if( !i2c_check_functionality(adapter, I2C_FUNC_SMBUS_BYTE_DATA
       | I2C_FUNC_SMBUS_WRITE_BYTE)) {
       pr_err("igb: i2c adaptor does not support required smbus/i2c modes\n");
       return(-ENODEV);
   }

   // success;

   strlcpy(info->type, IGB_VC_SFP, I2C_NAME_SIZE);
   return(0);
}

// probe sfp cage i2c;
// called for each i2c device after detecting, by the i2c core;
// the sfp may not be plugegd in yet, not much to do here;

static int
igb_vc_i2c_probe(struct i2c_client *client, const struct i2c_device_id *id)
{
   int ret = -ENODEV;

   // EEPROM probe;
   // create sysfs entries for sfp info;

   if(client->addr == igb_vc_i2c_addrs[0]) {
       vc_client[SFP_EEPROM] = client;
   }

   // DMI probe;

   if(client->addr == igb_vc_i2c_addrs[1]) {
       vc_client[SFP_DMI] = client;
       ret = 0;
   }

   return(ret);
}

// remove driver;

static int
igb_vc_i2c_remove(struct i2c_client *client)
{
   // remove sysfs entries;
   vc_client[SFP_EEPROM] = NULL;
   vc_client[SFP_DMI] = NULL;
   return(0);
}

static const struct i2c_device_id igb_vc_i2c_id[] = {
   { IGB_VC_SFP, 0 },
   {},
};

static struct i2c_driver igb_vc_i2c_driver = {
   .class = I2C_CLASS_HWMON,
   .driver = {
       .name = IGB_VC_SFP,
   },
   .address_list = igb_vc_i2c_addrs,
   .probe = igb_vc_i2c_probe,
   .remove = igb_vc_i2c_remove,
   .id_table = igb_vc_i2c_id,
   .detect = igb_vc_i2c_detect,
};


static struct class *igb_uio_class;
struct cdev cdev;
static dev_t devid;
static struct device *cldev;
static int wan_major;

static s32
igb_uio_open(struct inode *inode, struct file *file)
{
        u32 minor_number;

        minor_number = iminor(inode);
        if (minor_number)
            return -ENODEV;

        return 0;
}

static long
igb_uio_ioctl(struct file *file, u32 cmd, unsigned long arg)
{
   s32 rv = 0;
   struct mdio_fop fop;
   struct i2c_client *client;
   struct mii_bus *bus;
   int gpio;

   if (copy_from_user(&fop,
           (struct mdio_fop *)arg, sizeof(struct mdio_fop)))
        return -EFAULT;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,14,114)
    bus = vc_mdio_get(fop.dev_func);
    if (IS_ERR(bus)) {
        return PTR_ERR(bus);
    }
#else
    if (unlikely(!vc_mdio_bus)) {
        return -ENODEV;
    }
    bus = vc_mdio_bus;
#endif
   switch (cmd) {

        case MDIOBB_READ:
       rv = mdiobus_read(bus, fop.addr, fop.reg);
       fop.data = rv;
       if (rv < 0)
           printk("MDIO READ ERROR %d\n", rv);
       else
           rv = 0;

       copy_to_user((struct mdio_fop *)arg, &fop,
                   sizeof(struct mdio_fop));

       break;
        case MDIOBB_WRITE:
       rv = mdiobus_write(bus, fop.addr, fop.reg, fop.data);
       if (rv < 0)
           printk("MDIO WRITE ERROR %d\n", rv);
       else
           rv = 0;
                break;
   case GPIO_RESET:
       gpio = igb_vc5x0_reset_gpio[fop.addr];
       if(gpio >= 0) {
           printk("resetting func %d sw/phy\n", fop.addr);
           gpio_set_value(gpio, 0);
           usleep_range(100, 1000);
           gpio_set_value(gpio, 1);
       }
       break;
   case I2C_OPEN:
       i2c_add_driver(&igb_vc_i2c_driver);
       break;
   case I2C_READ_BYTE_OP:
       client = vc_client[SFP_EEPROM];
       if (!client)
           return(-ENODEV);
       else {
           if (copy_from_user(&fop, (struct mdio_fop *)arg, sizeof(fop)))
                       return -EFAULT;
           fop.data = i2c_smbus_read_byte_data(client, fop.reg);
           copy_to_user((struct mdio_fop *)arg, &fop, sizeof(fop));
       }
   case I2C_CLOSE:
       i2c_del_driver(&igb_vc_i2c_driver);
       break;
   default:
       rv = -EINVAL;
       break;
        }
        return rv;
}

static const struct file_operations igb_uio_fops = {
   .owner          = THIS_MODULE,
   .unlocked_ioctl = igb_uio_ioctl,
   .open           = igb_uio_open,
   .release        = NULL,
   .llseek         = noop_llseek,
};

#endif //NON_VELOCLOUD_KERNEL


/* sriov sysfs */
static ssize_t
show_max_vfs(struct device *dev, struct device_attribute *attr,
	     char *buf)
{
	return snprintf(buf, 10, "%u\n", dev_num_vf(dev));
}

static ssize_t
store_max_vfs(struct device *dev, struct device_attribute *attr,
	      const char *buf, size_t count)
{
	int err = 0;
	unsigned long max_vfs;
	struct pci_dev *pdev = to_pci_dev(dev);

	if (0 != kstrtoul(buf, 0, &max_vfs))
		return -EINVAL;

	if (0 == max_vfs)
		pci_disable_sriov(pdev);
	else if (0 == pci_num_vf(pdev))
		err = pci_enable_sriov(pdev, max_vfs);
	else /* do nothing if change max_vfs number */
		err = -EINVAL;

	return err ? err : count;
}

static DEVICE_ATTR(max_vfs, S_IRUGO | S_IWUSR, show_max_vfs, store_max_vfs);

static struct attribute *dev_attrs[] = {
	&dev_attr_max_vfs.attr,
	NULL,
};

static const struct attribute_group dev_attr_grp = {
	.attrs = dev_attrs,
};

#ifndef HAVE_PCI_MSI_MASK_IRQ
/*
 * It masks the msix on/off of generating MSI-X messages.
 */
static void
igbuio_msix_mask_irq(struct msi_desc *desc, s32 state)
{
	u32 mask_bits = desc->masked;
	unsigned int offset = desc->msi_attrib.entry_nr * PCI_MSIX_ENTRY_SIZE +
						PCI_MSIX_ENTRY_VECTOR_CTRL;

	if (state != 0)
		mask_bits &= ~PCI_MSIX_ENTRY_CTRL_MASKBIT;
	else
		mask_bits |= PCI_MSIX_ENTRY_CTRL_MASKBIT;

	if (mask_bits != desc->masked) {
		writel(mask_bits, desc->mask_base + offset);
		readl(desc->mask_base);
		desc->masked = mask_bits;
	}
}

/*
 * It masks the msi on/off of generating MSI messages.
 */
static void
igbuio_msi_mask_irq(struct pci_dev *pdev, struct msi_desc *desc, int32_t state)
{
	u32 mask_bits = desc->masked;
	u32 offset = desc->irq - pdev->irq;
	u32 mask = 1 << offset;

	if (!desc->msi_attrib.maskbit)
		return;

	if (state != 0)
		mask_bits &= ~mask;
	else
		mask_bits |= mask;

	if (mask_bits != desc->masked) {
		pci_write_config_dword(pdev, desc->mask_pos, mask_bits);
		desc->masked = mask_bits;
	}
}

static void
igbuio_mask_irq(struct pci_dev *pdev, enum rte_intr_mode mode, s32 irq_state)
{
	struct msi_desc *desc;
	struct list_head *msi_list;

#ifdef HAVE_MSI_LIST_IN_GENERIC_DEVICE
	msi_list = &pdev->dev.msi_list;
#else
	msi_list = &pdev->msi_list;
#endif

	if (mode == RTE_INTR_MODE_MSIX) {
		list_for_each_entry(desc, msi_list, list)
			igbuio_msix_mask_irq(desc, irq_state);
	} else if (mode == RTE_INTR_MODE_MSI) {
		list_for_each_entry(desc, msi_list, list)
			igbuio_msi_mask_irq(pdev, desc, irq_state);
	}
}
#endif

/**
 * This is the irqcontrol callback to be registered to uio_info.
 * It can be used to disable/enable interrupt from user space processes.
 *
 * @param info
 *  pointer to uio_info.
 * @param irq_state
 *  state value. 1 to enable interrupt, 0 to disable interrupt.
 *
 * @return
 *  - On success, 0.
 *  - On failure, a negative value.
 */
static int
igbuio_pci_irqcontrol(struct uio_info *info, s32 irq_state)
{
	struct rte_uio_pci_dev *udev = info->priv;
	struct pci_dev *pdev = udev->pdev;

#ifdef HAVE_PCI_MSI_MASK_IRQ
	struct irq_data *irq = irq_get_irq_data(udev->info.irq);
#endif

	pci_cfg_access_lock(pdev);

	if (udev->mode == RTE_INTR_MODE_MSIX || udev->mode == RTE_INTR_MODE_MSI) {
#ifdef HAVE_PCI_MSI_MASK_IRQ
		if (irq_state == 1)
			pci_msi_unmask_irq(irq);
		else
			pci_msi_mask_irq(irq);
#else
		igbuio_mask_irq(pdev, udev->mode, irq_state);
#endif
	}

	if (udev->mode == RTE_INTR_MODE_LEGACY)
		pci_intx(pdev, !!irq_state);

	pci_cfg_access_unlock(pdev);

	return 0;
}

/**
 * This is interrupt handler which will check if the interrupt is for the right device.
 * If yes, disable it here and will be enable later.
 */
static irqreturn_t
igbuio_pci_irqhandler(int irq, void *dev_id)
{
	struct rte_uio_pci_dev *udev = (struct rte_uio_pci_dev *)dev_id;
	struct uio_info *info = &udev->info;

	/* Legacy mode need to mask in hardware */
	if (udev->mode == RTE_INTR_MODE_LEGACY &&
	    !pci_check_and_mask_intx(udev->pdev))
		return IRQ_NONE;

	uio_event_notify(info);

	/* Message signal mode, no share IRQ and automasked */
	return IRQ_HANDLED;
}

static int
igbuio_pci_enable_interrupts(struct rte_uio_pci_dev *udev)
{
	int err = 0;
#ifndef HAVE_ALLOC_IRQ_VECTORS
	struct msix_entry msix_entry;
#endif

	switch (igbuio_intr_mode_preferred) {
	case RTE_INTR_MODE_MSIX:
		/* Only 1 msi-x vector needed */
#ifndef HAVE_ALLOC_IRQ_VECTORS
		msix_entry.entry = 0;
		if (pci_enable_msix(udev->pdev, &msix_entry, 1) == 0) {
			dev_dbg(&udev->pdev->dev, "using MSI-X");
			udev->info.irq_flags = IRQF_NO_THREAD;
			udev->info.irq = msix_entry.vector;
			udev->mode = RTE_INTR_MODE_MSIX;
			break;
		}
#else
		if (pci_alloc_irq_vectors(udev->pdev, 1, 1, PCI_IRQ_MSIX) == 1) {
			dev_dbg(&udev->pdev->dev, "using MSI-X");
			udev->info.irq_flags = IRQF_NO_THREAD;
			udev->info.irq = pci_irq_vector(udev->pdev, 0);
			udev->mode = RTE_INTR_MODE_MSIX;
			break;
		}
#endif

	/* falls through - to MSI */
	case RTE_INTR_MODE_MSI:
#ifndef HAVE_ALLOC_IRQ_VECTORS
		if (pci_enable_msi(udev->pdev) == 0) {
			dev_dbg(&udev->pdev->dev, "using MSI");
			udev->info.irq_flags = IRQF_NO_THREAD;
			udev->info.irq = udev->pdev->irq;
			udev->mode = RTE_INTR_MODE_MSI;
			break;
		}
#else
		if (pci_alloc_irq_vectors(udev->pdev, 1, 1, PCI_IRQ_MSI) == 1) {
			dev_dbg(&udev->pdev->dev, "using MSI");
			udev->info.irq_flags = IRQF_NO_THREAD;
			udev->info.irq = pci_irq_vector(udev->pdev, 0);
			udev->mode = RTE_INTR_MODE_MSI;
			break;
		}
#endif
	/* falls through - to INTX */
	case RTE_INTR_MODE_LEGACY:
		if (pci_intx_mask_supported(udev->pdev)) {
			dev_dbg(&udev->pdev->dev, "using INTX");
			udev->info.irq_flags = IRQF_SHARED | IRQF_NO_THREAD;
			udev->info.irq = udev->pdev->irq;
			udev->mode = RTE_INTR_MODE_LEGACY;
			break;
		}
		dev_notice(&udev->pdev->dev, "PCI INTX mask not supported\n");
	/* falls through - to no IRQ */
	case RTE_INTR_MODE_NONE:
		udev->mode = RTE_INTR_MODE_NONE;
		udev->info.irq = UIO_IRQ_NONE;
		break;

	default:
		dev_err(&udev->pdev->dev, "invalid IRQ mode %u",
			igbuio_intr_mode_preferred);
		udev->info.irq = UIO_IRQ_NONE;
		err = -EINVAL;
	}

	if (udev->info.irq != UIO_IRQ_NONE)
		err = request_irq(udev->info.irq, igbuio_pci_irqhandler,
				  udev->info.irq_flags, udev->info.name,
				  udev);
	dev_info(&udev->pdev->dev, "uio device registered with irq %ld\n",
		 udev->info.irq);

	return err;
}

static void
igbuio_pci_disable_interrupts(struct rte_uio_pci_dev *udev)
{
	if (udev->info.irq) {
		free_irq(udev->info.irq, udev);
		udev->info.irq = 0;
	}

#ifndef HAVE_ALLOC_IRQ_VECTORS
	if (udev->mode == RTE_INTR_MODE_MSIX)
		pci_disable_msix(udev->pdev);
	if (udev->mode == RTE_INTR_MODE_MSI)
		pci_disable_msi(udev->pdev);
#else
	if (udev->mode == RTE_INTR_MODE_MSIX ||
	    udev->mode == RTE_INTR_MODE_MSI)
		pci_free_irq_vectors(udev->pdev);
#endif
}


/**
 * This gets called while opening uio device file.
 */
static int
igbuio_pci_open(struct uio_info *info, struct inode *inode)
{
	struct rte_uio_pci_dev *udev = info->priv;
	struct pci_dev *dev = udev->pdev;
	int err;

	if (atomic_inc_return(&udev->refcnt) != 1)
		return 0;

	/* set bus master, which was cleared by the reset function */
	pci_set_master(dev);

	/* enable interrupts */
	err = igbuio_pci_enable_interrupts(udev);
	if (err) {
		atomic_dec(&udev->refcnt);
		dev_err(&dev->dev, "Enable interrupt fails\n");
	}
	return err;
}

static int
igbuio_pci_release(struct uio_info *info, struct inode *inode)
{
	struct rte_uio_pci_dev *udev = info->priv;
	struct pci_dev *dev = udev->pdev;

	if (atomic_dec_and_test(&udev->refcnt)) {
		/* disable interrupts */
		igbuio_pci_disable_interrupts(udev);

		/* stop the device from further DMA */
		pci_clear_master(dev);
	}

	return 0;
}

/* Remap pci resources described by bar #pci_bar in uio resource n. */
static int
igbuio_pci_setup_iomem(struct pci_dev *dev, struct uio_info *info,
		       int n, int pci_bar, const char *name)
{
	unsigned long addr, len;
	void *internal_addr;

	if (n >= ARRAY_SIZE(info->mem))
		return -EINVAL;

	addr = pci_resource_start(dev, pci_bar);
	len = pci_resource_len(dev, pci_bar);
	if (addr == 0 || len == 0)
		return -1;
	if (wc_activate == 0) {
		internal_addr = ioremap(addr, len);
		if (internal_addr == NULL)
			return -1;
	} else {
		internal_addr = NULL;
	}
	info->mem[n].name = name;
	info->mem[n].addr = addr;
	info->mem[n].internal_addr = internal_addr;
	info->mem[n].size = len;
	info->mem[n].memtype = UIO_MEM_PHYS;
	return 0;
}

/* Get pci port io resources described by bar #pci_bar in uio resource n. */
static int
igbuio_pci_setup_ioport(struct pci_dev *dev, struct uio_info *info,
		int n, int pci_bar, const char *name)
{
	unsigned long addr, len;

	if (n >= ARRAY_SIZE(info->port))
		return -EINVAL;

	addr = pci_resource_start(dev, pci_bar);
	len = pci_resource_len(dev, pci_bar);
	if (addr == 0 || len == 0)
		return -EINVAL;

	info->port[n].name = name;
	info->port[n].start = addr;
	info->port[n].size = len;
	info->port[n].porttype = UIO_PORT_X86;

	return 0;
}

/* Unmap previously ioremap'd resources */
static void
igbuio_pci_release_iomem(struct uio_info *info)
{
	int i;

	for (i = 0; i < MAX_UIO_MAPS; i++) {
		if (info->mem[i].internal_addr)
			iounmap(info->mem[i].internal_addr);
	}
}

static int
igbuio_setup_bars(struct pci_dev *dev, struct uio_info *info)
{
	int i, iom, iop, ret;
	unsigned long flags;
	static const char *bar_names[PCI_STD_RESOURCE_END + 1]  = {
		"BAR0",
		"BAR1",
		"BAR2",
		"BAR3",
		"BAR4",
		"BAR5",
	};

	iom = 0;
	iop = 0;

	for (i = 0; i < ARRAY_SIZE(bar_names); i++) {
		if (pci_resource_len(dev, i) != 0 &&
				pci_resource_start(dev, i) != 0) {
			flags = pci_resource_flags(dev, i);
			if (flags & IORESOURCE_MEM) {
				ret = igbuio_pci_setup_iomem(dev, info, iom,
							     i, bar_names[i]);
				if (ret != 0)
					return ret;
				iom++;
			} else if (flags & IORESOURCE_IO) {
				ret = igbuio_pci_setup_ioport(dev, info, iop,
							      i, bar_names[i]);
				if (ret != 0)
					return ret;
				iop++;
			}
		}
	}

	return (iom != 0 || iop != 0) ? ret : -ENOENT;
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 8, 0)
static int __devinit
#else
static int
#endif
igbuio_pci_probe(struct pci_dev *dev, const struct pci_device_id *id)
{
	struct rte_uio_pci_dev *udev;
	dma_addr_t map_dma_addr;
	void *map_addr;
	int err;
#ifndef NON_VELOCLOUD_KERNEL
	unsigned long vc_id;
	int i;
#endif //NON_VELOCLOUD_KERNEL

#ifdef HAVE_PCI_IS_BRIDGE_API
	if (pci_is_bridge(dev)) {
		dev_warn(&dev->dev, "Ignoring PCI bridge device\n");
		return -ENODEV;
	}
#endif

	udev = kzalloc(sizeof(struct rte_uio_pci_dev), GFP_KERNEL);
	if (!udev)
		return -ENOMEM;

	/*
	 * enable device: ask low-level code to enable I/O and
	 * memory
	 */
	err = pci_enable_device(dev);
	if (err != 0) {
		dev_err(&dev->dev, "Cannot enable PCI device\n");
		goto fail_free;
	}

	/* enable bus mastering on the device */
	pci_set_master(dev);

	/* remap IO memory */
	err = igbuio_setup_bars(dev, &udev->info);
	if (err != 0)
		goto fail_release_iomem;

	/* set 64-bit DMA mask */
	err = pci_set_dma_mask(dev,  DMA_BIT_MASK(64));
	if (err != 0) {
		dev_err(&dev->dev, "Cannot set DMA mask\n");
		goto fail_release_iomem;
	}

	err = pci_set_consistent_dma_mask(dev, DMA_BIT_MASK(64));
	if (err != 0) {
		dev_err(&dev->dev, "Cannot set consistent DMA mask\n");
		goto fail_release_iomem;
	}

	/* fill uio infos */
	udev->info.name = "igb_uio";
	udev->info.version = "0.1";
	udev->info.irqcontrol = igbuio_pci_irqcontrol;
	udev->info.open = igbuio_pci_open;
	udev->info.release = igbuio_pci_release;
	udev->info.priv = udev;
	udev->pdev = dev;
	atomic_set(&udev->refcnt, 0);

	err = sysfs_create_group(&dev->dev.kobj, &dev_attr_grp);
	if (err != 0)
		goto fail_release_iomem;

	/* register uio driver */
	err = uio_register_device(&dev->dev, &udev->info);
	if (err != 0)
		goto fail_remove_group;

	pci_set_drvdata(dev, udev);

	/*
	 * Doing a harmless dma mapping for attaching the device to
	 * the iommu identity mapping if kernel boots with iommu=pt.
	 * Note this is not a problem if no IOMMU at all.
	 */
	map_addr = dma_alloc_coherent(&dev->dev, 1024, &map_dma_addr,
			GFP_KERNEL);
	if (map_addr)
		memset(map_addr, 0, 1024);

	if (!map_addr)
		dev_info(&dev->dev, "dma mapping failed\n");
	else {
		dev_info(&dev->dev, "mapping 1K dma=%#llx host=%p\n",
			 (unsigned long long)map_dma_addr, map_addr);

		dma_free_coherent(&dev->dev, 1024, map_addr, map_dma_addr);
		dev_info(&dev->dev, "unmapping 1K dma=%#llx host=%p\n",
			 (unsigned long long)map_dma_addr, map_addr);
	}

#ifndef NON_VELOCLOUD_KERNEL
    /* Stock kernel without VC support */
    if (! vc_dmi)
        return err;

   vc_id = (unsigned long)vc_dmi->driver_data;

    switch(vc_id) {
	 case VC_EDGE520:
	 case VC_EDGE520B:
         case VC_EDGE540:
         case VC_EDGE540B:
                 break;
         default:
                 return(err);
         }

    for (i = 0; i < WAN_LINK_MAX_DEVS; i++) {
        if (dev->bus->number == vc_hw_edge540.pci_addrs[i].bus &&
            dev->devfn == vc_hw_edge540.pci_addrs[i].devfn) {
            break;
        }
    }

    if (i == WAN_LINK_MAX_DEVS)
        return err;
    else {
        if (atomic_read (&vc_hw_edge540.ref_count) == 0) {
            atomic_inc(&vc_hw_edge540.ref_count);
            dev_info(&dev->dev, "wan link: %s\n", vc_dmi->ident);
        } else {
            atomic_inc(&vc_hw_edge540.ref_count);
            return (err);
        }
    }

    igb_uio_class = class_create(THIS_MODULE, "wan");
    if (IS_ERR(igb_uio_class)) {
                 err = PTR_ERR(igb_uio_class);
        dev_err(&dev->dev, "Cannot create WAN class\n");
        goto fail_remove_group;
    }

    err = alloc_chrdev_region(&devid, 0, WAN_MAX_DEVS, "wan");
    if (err) {
         class_destroy(igb_uio_class);
        goto fail_remove_group;
    }

    wan_major = MAJOR(devid);

    cldev = device_create(igb_uio_class, NULL, MKDEV(wan_major, 0), NULL, "wan");
    if (IS_ERR(cldev)) {
        err = PTR_ERR(cldev);
        unregister_chrdev_region(devid, WAN_MAX_DEVS);
        class_destroy(igb_uio_class);
        dev_err(&dev->dev, "Unable to create device class wan\n");
        goto fail_remove_group;
    }

    cdev_init(&cdev, &igb_uio_fops);

    err = cdev_add(&cdev, devid, 1);
    if (err) {
       device_destroy(igb_uio_class, MKDEV(wan_major, 0));
       class_destroy(igb_uio_class);
       unregister_chrdev_region(devid, WAN_MAX_DEVS);
       dev_err(&dev->dev, "Unable to add device node 'wan'\n");
    }
#endif //NON_VELOCLOUD_KERNEL

	return 0;

fail_remove_group:
	sysfs_remove_group(&dev->dev.kobj, &dev_attr_grp);
fail_release_iomem:
	igbuio_pci_release_iomem(&udev->info);
	pci_disable_device(dev);
fail_free:
	kfree(udev);

	return err;
}

static void
igbuio_pci_remove(struct pci_dev *dev)
{
	struct rte_uio_pci_dev *udev = pci_get_drvdata(dev);
#ifndef NON_VELOCLOUD_KERNEL
    int i;
    unsigned long vc_id;
#endif //NON_VELOCLOUD_KERNEL

	igbuio_pci_release(&udev->info, NULL);

	sysfs_remove_group(&dev->dev.kobj, &dev_attr_grp);
	uio_unregister_device(&udev->info);
	igbuio_pci_release_iomem(&udev->info);
	pci_disable_device(dev);
	pci_set_drvdata(dev, NULL);
	kfree(udev);

#ifndef NON_VELOCLOUD_KERNEL
    /* Stock kernel without VC support */
    if (! vc_dmi)
        return;

    vc_id = (unsigned long)vc_dmi->driver_data;

    switch(vc_id) {
	 case VC_EDGE520:
	 case VC_EDGE520B:
         case VC_EDGE540:
         case VC_EDGE540B:
                 break;
         default:
                 return;
    }

    for (i = 0; i < WAN_LINK_MAX_DEVS; i++) {
        if (dev->bus->number == vc_hw_edge540.pci_addrs[i].bus &&
            dev->devfn == vc_hw_edge540.pci_addrs[i].devfn) {
            break;
        }
    }

    if (i == WAN_LINK_MAX_DEVS)
        return;
    else {
        atomic_dec(&vc_hw_edge540.ref_count);

        if (atomic_read (&vc_hw_edge540.ref_count) == 0) {
            cdev_del(&cdev);
            device_destroy(igb_uio_class, MKDEV(wan_major, 0));
            class_destroy(igb_uio_class);
            unregister_chrdev_region(devid, WAN_MAX_DEVS);
        }
    }
#endif //NON_VELOCLOUD_KERNEL
}

static int
igbuio_config_intr_mode(char *intr_str)
{
	if (!intr_str) {
		pr_info("Use MSIX interrupt by default\n");
		return 0;
	}

	if (!strcmp(intr_str, RTE_INTR_MODE_MSIX_NAME)) {
		igbuio_intr_mode_preferred = RTE_INTR_MODE_MSIX;
		pr_info("Use MSIX interrupt\n");
	} else if (!strcmp(intr_str, RTE_INTR_MODE_MSI_NAME)) {
		igbuio_intr_mode_preferred = RTE_INTR_MODE_MSI;
		pr_info("Use MSI interrupt\n");
	} else if (!strcmp(intr_str, RTE_INTR_MODE_LEGACY_NAME)) {
		igbuio_intr_mode_preferred = RTE_INTR_MODE_LEGACY;
		pr_info("Use legacy interrupt\n");
	} else {
		pr_info("Error: bad parameter - %s\n", intr_str);
		return -EINVAL;
	}

	return 0;
}

static struct pci_driver igbuio_pci_driver = {
	.name = "igb_uio",
	.id_table = NULL,
	.probe = igbuio_pci_probe,
	.remove = igbuio_pci_remove,
};

static int __init
igbuio_pci_init_module(void)
{
	int ret;

	if (igbuio_kernel_is_locked_down()) {
		pr_err("Not able to use module, kernel lock down is enabled\n");
		return -EINVAL;
	}

	if (wc_activate != 0)
		pr_info("wc_activate is set\n");

	ret = igbuio_config_intr_mode(intr_mode);
	if (ret < 0)
		return ret;

	return pci_register_driver(&igbuio_pci_driver);
}

static void __exit
igbuio_pci_exit_module(void)
{
	pci_unregister_driver(&igbuio_pci_driver);
}

module_init(igbuio_pci_init_module);
module_exit(igbuio_pci_exit_module);

module_param(intr_mode, charp, S_IRUGO);
MODULE_PARM_DESC(intr_mode,
"igb_uio interrupt mode (default=msix):\n"
"    " RTE_INTR_MODE_MSIX_NAME "       Use MSIX interrupt\n"
"    " RTE_INTR_MODE_MSI_NAME "        Use MSI interrupt\n"
"    " RTE_INTR_MODE_LEGACY_NAME "     Use Legacy interrupt\n"
"\n");

module_param(wc_activate, int, 0);
MODULE_PARM_DESC(wc_activate,
"Activate support for write combining (WC) (default=0)\n"
"    0 - disable\n"
"    other - enable\n");

MODULE_DESCRIPTION("UIO driver for Intel IGB PCI cards");
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Intel Corporation");
