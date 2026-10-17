#include "pin_uv.h"
#include "credential.h"
#include "stm32f4xx_hal.h"
#include "stm32f4xx_hal_flash_ex.h"
#include "mbedtls/aes.h"
#include "mbedtls/ecp.h"
#include "mbedtls/sha256.h"
#include <stddef.h>
#include <string.h>

#define PIN_FLASH_ADDRESS 0x080c0000u
#define PIN_FLASH_SECTOR FLASH_SECTOR_10
#define PIN_RECORD_MAGIC 0x31504e46u
#define PIN_RECORD_COMMIT 0x54494d43u
#define PIN_RETRIES 8u

typedef struct {
 uint32_t magic;
 uint8_t pin_hash[16];
 uint8_t digest[32];
 uint32_t commit;
} pin_record;

_Static_assert(sizeof(pin_record)==56,"PIN record must be word aligned");

static mbedtls_mpi private_key;
static bool private_key_ready;
static bool token_ready;
static uint8_t pin_token[32];

static bool erase_pin_sector(void){
 if(FLASH_WaitForLastOperation(50000u)!=HAL_OK)return false;
 __HAL_FLASH_CLEAR_FLAG(FLASH_FLAG_EOP|FLASH_FLAG_OPERR|FLASH_FLAG_WRPERR|
                        FLASH_FLAG_PGAERR|FLASH_FLAG_PGPERR|FLASH_FLAG_PGSERR);
 CLEAR_BIT(FLASH->CR,FLASH_CR_PSIZE);
 SET_BIT(FLASH->CR,FLASH_PSIZE_WORD);
 MODIFY_REG(FLASH->CR,FLASH_CR_SNB,(PIN_FLASH_SECTOR<<3));
 SET_BIT(FLASH->CR,FLASH_CR_SER);
 SET_BIT(FLASH->CR,FLASH_CR_STRT);
 HAL_StatusTypeDef status=FLASH_WaitForLastOperation(50000u);
 CLEAR_BIT(FLASH->CR,FLASH_CR_SER|FLASH_CR_SNB);
 if(status!=HAL_OK)return false;
 uint32_t cache=FLASH->ACR&(FLASH_ACR_ICEN|FLASH_ACR_DCEN);
 __HAL_FLASH_INSTRUCTION_CACHE_DISABLE();__HAL_FLASH_DATA_CACHE_DISABLE();
 __HAL_FLASH_INSTRUCTION_CACHE_RESET();__HAL_FLASH_DATA_CACHE_RESET();
 FLASH->ACR|=cache;
 return true;
}

static bool record_read(pin_record *record){
 memcpy(record,(const void*)PIN_FLASH_ADDRESS,sizeof *record);
 if(record->magic!=PIN_RECORD_MAGIC||record->commit!=PIN_RECORD_COMMIT)return false;
 uint8_t digest[32];
 crypto_hash(record,offsetof(pin_record,digest),digest);
 bool valid=!memcmp(digest,record->digest,sizeof digest);
 memset(digest,0,sizeof digest);
 return valid;
}

bool pin_uv_configured(void){
 pin_record record;
 bool configured=record_read(&record);
 memset(&record,0,sizeof record);
 return configured;
}

bool pin_uv_set_pin_hash(const uint8_t hash[16]){
 pin_record record={0};
 record.magic=PIN_RECORD_MAGIC;
 memcpy(record.pin_hash,hash,sizeof record.pin_hash);
 record.commit=PIN_RECORD_COMMIT;
 crypto_hash(&record,offsetof(pin_record,digest),record.digest);
 if(HAL_FLASH_Unlock()!=HAL_OK)return false;
 bool ok=erase_pin_sector();
 const uint32_t *words=(const uint32_t*)&record;
 for(size_t i=0;ok&&i<sizeof record/4;i++)
  ok=HAL_FLASH_Program(FLASH_TYPEPROGRAM_WORD,PIN_FLASH_ADDRESS+(uint32_t)i*4,words[i])==HAL_OK;
 HAL_FLASH_Lock();
 pin_record verify;
 ok=ok&&record_read(&verify)&&!memcmp(verify.pin_hash,hash,16);
 memset(&record,0,sizeof record);memset(&verify,0,sizeof verify);
 return ok;
}

bool pin_uv_set_from_console(const uint8_t *pin,size_t length){
 if(!pin||length<4||length>63)return false;
 for(size_t i=0;i<length;i++)if(pin[i]<'0'||pin[i]>'9')return false;
 uint8_t hash[32];
 crypto_hash(pin,length,hash);
 bool ok=pin_uv_set_pin_hash(hash);
 if(ok)pin_uv_clear_token();
 memset(hash,0,sizeof hash);
 return ok;
}

bool pin_uv_get_key_agreement(uint8_t x[32],uint8_t y[32]){
 mbedtls_ecp_group group;
 mbedtls_ecp_point public_key;
 mbedtls_ecp_group_init(&group);mbedtls_ecp_point_init(&public_key);
 if(private_key_ready){mbedtls_mpi_free(&private_key);private_key_ready=false;}
 mbedtls_mpi_init(&private_key);
 bool ok=!mbedtls_ecp_group_load(&group,MBEDTLS_ECP_DP_SECP256R1)
  &&!mbedtls_ecp_gen_keypair(&group,&private_key,&public_key,crypto_random,0)
  &&!mbedtls_mpi_write_binary(&public_key.X,x,32)
  &&!mbedtls_mpi_write_binary(&public_key.Y,y,32);
 private_key_ready=ok;
 if(!ok)mbedtls_mpi_free(&private_key);
 mbedtls_ecp_point_free(&public_key);mbedtls_ecp_group_free(&group);
 return ok;
}

bool pin_uv_derive_shared_secret(const uint8_t x[32],const uint8_t y[32],
                                uint8_t shared_secret[32]){
 if(!private_key_ready)return false;
 mbedtls_ecp_group group;mbedtls_ecp_point peer,shared;
 mbedtls_ecp_group_init(&group);mbedtls_ecp_point_init(&peer);mbedtls_ecp_point_init(&shared);
 uint8_t encoded[65],secret[32];encoded[0]=4;memcpy(encoded+1,x,32);memcpy(encoded+33,y,32);
 bool ok=!mbedtls_ecp_group_load(&group,MBEDTLS_ECP_DP_SECP256R1)
  &&!mbedtls_ecp_point_read_binary(&group,&peer,encoded,sizeof encoded)
  &&!mbedtls_ecp_check_pubkey(&group,&peer)
  &&!mbedtls_ecp_mul(&group,&shared,&private_key,&peer,crypto_random,0)
  &&!mbedtls_mpi_write_binary(&shared.X,secret,sizeof secret);
 if(ok)mbedtls_sha256(secret,sizeof secret,shared_secret,0);
 mbedtls_mpi_free(&private_key);private_key_ready=false;
 mbedtls_ecp_point_free(&shared);mbedtls_ecp_point_free(&peer);mbedtls_ecp_group_free(&group);
 memset(encoded,0,sizeof encoded);memset(secret,0,sizeof secret);
 return ok;
}

bool pin_uv_hmac(const uint8_t key[32],const uint8_t *data,size_t length,
                 uint8_t output[32]){
 uint8_t inner_pad[64],outer_pad[64],inner_hash[32];
 memset(inner_pad,0x36,sizeof inner_pad);memset(outer_pad,0x5c,sizeof outer_pad);
 for(size_t i=0;i<32;i++){inner_pad[i]^=key[i];outer_pad[i]^=key[i];}
 mbedtls_sha256_context sha;mbedtls_sha256_init(&sha);mbedtls_sha256_starts(&sha,0);
 mbedtls_sha256_update(&sha,inner_pad,sizeof inner_pad);mbedtls_sha256_update(&sha,data,length);
 mbedtls_sha256_finish(&sha,inner_hash);mbedtls_sha256_starts(&sha,0);
 mbedtls_sha256_update(&sha,outer_pad,sizeof outer_pad);mbedtls_sha256_update(&sha,inner_hash,sizeof inner_hash);
 mbedtls_sha256_finish(&sha,output);mbedtls_sha256_free(&sha);
 memset(inner_pad,0,sizeof inner_pad);memset(outer_pad,0,sizeof outer_pad);memset(inner_hash,0,sizeof inner_hash);
 return true;
}

bool pin_uv_crypt(bool encrypt,const uint8_t key[32],const uint8_t *input,
                  size_t length,uint8_t *output){
 if(!length||(length&15u)||length>64)return false;
 mbedtls_aes_context aes;uint8_t iv[16]={0};mbedtls_aes_init(&aes);
 bool ok=(encrypt?mbedtls_aes_setkey_enc(&aes,key,256):mbedtls_aes_setkey_dec(&aes,key,256))==0
  &&mbedtls_aes_crypt_cbc(&aes,encrypt?MBEDTLS_AES_ENCRYPT:MBEDTLS_AES_DECRYPT,
                          length,iv,input,output)==0;
 mbedtls_aes_free(&aes);memset(iv,0,sizeof iv);
 return ok;
}

bool pin_uv_check_pin_hash(const uint8_t hash[16]){
 pin_record record;bool ok=record_read(&record)&&!memcmp(record.pin_hash,hash,16);
 memset(&record,0,sizeof record);return ok;
}

bool pin_uv_set_token(const uint8_t token[32]){
 memcpy(pin_token,token,sizeof pin_token);token_ready=true;return true;
}

bool pin_uv_verify_token_auth(const uint8_t *data,size_t length,const uint8_t auth[16]){
 if(!token_ready)return false;
 uint8_t expected[32];pin_uv_hmac(pin_token,data,length,expected);
 bool valid=!memcmp(expected,auth,16);memset(expected,0,sizeof expected);
 return valid;
}

void pin_uv_clear_token(void){
 memset(pin_token,0,sizeof pin_token);token_ready=false;
}
