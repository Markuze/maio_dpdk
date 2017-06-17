#ifndef VC_IGB_UIO_IOCTL_H
#define VC_IGB_UIO_IOCTL_H

#include <linux/ioctl.h>

/* XXX Fixme -- 'unsigned int' does not transpose to u32 necessarily. */
struct mdio_fop {
        unsigned int addr;
        unsigned int reg;
	unsigned int data;
};

#define MDIOBB_READ	 0x101
#define MDIOBB_WRITE	 0x102
#define GPIO_RESET	 0x103
#define I2C_OPEN	 0x104
#define I2C_READ_BYTE_OP 0x105
#define I2C_CLOSE	 0x106

#endif
