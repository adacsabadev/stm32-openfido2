#include "log.h"
#include "usb_composite.h"
void log_init(void) {}
void log_puts(const char *text) { while (*text) usb_cdc_write((const uint8_t *)text++, 1); }
void log_hex(const uint8_t *data, uint32_t length) { usb_cdc_write(data, length); }
