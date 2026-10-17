#pragma once
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
typedef struct {
 uint32_t magic,sequence;
 uint8_t id[32],rp[32],secret[32];
 uint32_t counter;
 uint8_t digest[32];
 uint32_t commit;
} credential;
typedef struct {
 uint8_t id[32],rp[32];
 uint32_t counter;
 bool discoverable;
} credential_summary;
bool credential_lookup(const uint8_t id[32],const uint8_t rp[32],credential*out);
bool credential_lookup_resident(const uint8_t rp[32],credential*out,
                                uint8_t user_id[64],uint32_t*user_id_len);
bool credential_save(credential*c);
bool credential_save_resident(credential*c,const uint8_t*user_id,uint32_t user_id_len);
bool credential_room_for(uint32_t slots);
uint32_t credential_list_count(void);
bool credential_list_get(uint32_t index,credential_summary*out);
int crypto_random(void *ctx,uint8_t*out,size_t n);
void crypto_hash(const void*p,size_t n,uint8_t out[32]);
bool crypto_generate(credential*c,uint8_t x[32],uint8_t y[32]);
bool crypto_sign(const credential*c,const uint8_t*data,size_t n,uint8_t sig[80],size_t*len);
