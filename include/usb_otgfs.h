#pragma once
#include <stdint.h>
void usb_otgfs_init(void);
void usb_otgfs_irq(void);
int usb_otgfs_write(uint8_t endpoint,const uint8_t *data,uint16_t length);
uint8_t usb_otgfs_configured(void);
