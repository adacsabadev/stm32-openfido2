#pragma once
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

bool pin_uv_configured(void);
bool pin_uv_set_from_console(const uint8_t *pin, size_t length);
bool pin_uv_get_key_agreement(uint8_t x[32], uint8_t y[32]);
bool pin_uv_derive_shared_secret(const uint8_t x[32], const uint8_t y[32],
                                uint8_t shared_secret[32]);
bool pin_uv_hmac(const uint8_t key[32], const uint8_t *data, size_t length,
                 uint8_t output[32]);
bool pin_uv_crypt(bool encrypt, const uint8_t key[32], const uint8_t *input,
                  size_t length, uint8_t *output);
bool pin_uv_check_pin_hash(const uint8_t hash[16]);
bool pin_uv_set_pin_hash(const uint8_t hash[16]);
bool pin_uv_set_token(const uint8_t token[32]);
bool pin_uv_verify_token_auth(const uint8_t *data, size_t length,
                              const uint8_t auth[16]);
void pin_uv_clear_token(void);
