#pragma once
#include <stdint.h>
void log_init(void);
void log_puts(const char *text);
void log_hex(const uint8_t *data, uint32_t length);
