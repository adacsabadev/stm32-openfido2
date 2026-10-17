#pragma once
#include <stdint.h>
void platform_init(void);
uint32_t platform_millis(void);
void platform_idle(void);
void platform_usb_pins_init(void);
