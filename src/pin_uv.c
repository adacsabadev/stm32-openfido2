#include "pin_uv.h"
#include "credential.h"
#include "log.h"
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

static void pin_flash_log_hex(const char*label,uint32_t value){
 static const char digits[]="0123456789ABCDEF";
 char line[64];size_t used=0;
 while(*label&&used<sizeof line-13u)line[used++]=*label++;
 line[used++]='0';line[used++]='x';
 for(int shift=28;shift>=0;shift-=4)line[used++]=digits[(value>>shift)&15u];
 line[used++]='\r';line[used++]='\n';line[used]=0;log_puts(line);
}

static void pin_flash_log_number(const char*label,uint32_t value){
 char line[64];size_t used=0;
 while(*label&&used<sizeof line-13u)line[used++]=*label++;
 char digits[10];size_t count=0;
 do{digits[count++]=(char)('0'+value%10u);value/=10u;}while(value);
 while(count)line[used++]=digits[--count];
 line[used++]='\r';line[used++]='\n';line[used]=0;log_puts(line);
}

static bool erase_pin_sector(void){
 log_puts("PIN flash erase begin: sector 10 address 0x080C0000\r\n");
 HAL_StatusTypeDef ready=FLASH_WaitForLastOperation(50000u);
 if(ready!=HAL_OK){
  pin_flash_log_number("PIN flash erase pre-wait status=",ready);
  pin_flash_log_hex("PIN flash status register=",FLASH->SR);return false;
 }
 __HAL_FLASH_CLEAR_FLAG(FLASH_FLAG_EOP|FLASH_FLAG_OPERR|FLASH_FLAG_WRPERR|
                        FLASH_FLAG_PGAERR|FLASH_FLAG_PGPERR|FLASH_FLAG_PGSERR);
 CLEAR_BIT(FLASH->CR,FLASH_CR_PSIZE);
 SET_BIT(FLASH->CR,FLASH_PSIZE_WORD);
 MODIFY_REG(FLASH->CR,FLASH_CR_SNB,(PIN_FLASH_SECTOR<<3));
 SET_BIT(FLASH->CR,FLASH_CR_SER);
 SET_BIT(FLASH->CR,FLASH_CR_STRT);
 HAL_StatusTypeDef status=FLASH_WaitForLastOperation(50000u);
 CLEAR_BIT(FLASH->CR,FLASH_CR_SER|FLASH_CR_SNB);
 if(status!=HAL_OK){
  pin_flash_log_number("PIN flash erase failed status=",status);
  pin_flash_log_hex("PIN flash status register=",FLASH->SR);
  pin_flash_log_hex("PIN flash control register=",FLASH->CR);return false;
 }
 log_puts("PIN flash erase complete: sector 10\r\n");
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
 log_puts("PIN verifier update begin: address 0x080C0000 bytes=56\r\n");
 HAL_StatusTypeDef unlock=HAL_FLASH_Unlock();
 if(unlock!=HAL_OK){
  pin_flash_log_number("PIN flash unlock failed status=",unlock);
  pin_flash_log_hex("PIN flash control register=",FLASH->CR);return false;
 }
 bool ok=erase_pin_sector();
 const uint32_t *words=(const uint32_t*)&record;
 for(size_t i=0;ok&&i<sizeof record/4;i++){
  uint32_t address=PIN_FLASH_ADDRESS+(uint32_t)i*4;
  HAL_StatusTypeDef status=HAL_FLASH_Program(FLASH_TYPEPROGRAM_WORD,address,words[i]);
  if(status!=HAL_OK){
   pin_flash_log_hex("PIN flash program failed address=",address);
   pin_flash_log_number("PIN flash program status=",status);
   pin_flash_log_hex("PIN flash status register=",FLASH->SR);ok=false;
  }
 }
 HAL_FLASH_Lock();
 pin_record verify;
 ok=ok&&record_read(&verify)&&!memcmp(verify.pin_hash,hash,16);
 log_puts(ok?"PIN verifier update verified\r\n":"PIN verifier update failed verification\r\n");
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

bool pin_uv_change_from_console(const uint8_t *old_pin,size_t old_length,
                                const uint8_t *new_pin,size_t new_length){
 if(!old_pin||old_length<4||old_length>63||!new_pin||new_length<4||new_length>63)return false;
 for(size_t i=0;i<old_length;i++)if(old_pin[i]<'0'||old_pin[i]>'9')return false;
 for(size_t i=0;i<new_length;i++)if(new_pin[i]<'0'||new_pin[i]>'9')return false;
 uint8_t old_hash[32];crypto_hash(old_pin,old_length,old_hash);
 bool matches=pin_uv_check_pin_hash(old_hash);
 memset(old_hash,0,sizeof old_hash);
 return matches&&pin_uv_set_from_console(new_pin,new_length);
}

bool pin_uv_delete(void){
 log_puts("PIN deletion begin\r\n");
 HAL_StatusTypeDef unlock=HAL_FLASH_Unlock();
 if(unlock!=HAL_OK){
  pin_flash_log_number("PIN flash unlock failed status=",unlock);
  pin_flash_log_hex("PIN flash control register=",FLASH->CR);return false;
 }
 bool ok=erase_pin_sector();
 HAL_FLASH_Lock();
 pin_uv_clear_token();
 if(private_key_ready){mbedtls_mpi_free(&private_key);private_key_ready=false;}
 bool deleted=ok&&!pin_uv_configured();
 log_puts(deleted?"PIN deletion complete\r\n":"PIN deletion failed\r\n");
 return deleted;
}

bool pin_uv_get_key_agreement(uint8_t x[32],uint8_t y[32]){
 mbedtls_ecp_group group;
 mbedtls_ecp_point public_key;
 uint8_t encoded[65];size_t encoded_length=0;
 mbedtls_ecp_group_init(&group);mbedtls_ecp_point_init(&public_key);
 if(private_key_ready){mbedtls_mpi_free(&private_key);private_key_ready=false;}
 mbedtls_mpi_init(&private_key);
 bool ok=!mbedtls_ecp_group_load(&group,MBEDTLS_ECP_DP_SECP256R1)
  &&!mbedtls_ecp_gen_keypair(&group,&private_key,&public_key,crypto_random,0)
  &&!mbedtls_ecp_point_write_binary(&group,&public_key,MBEDTLS_ECP_PF_UNCOMPRESSED,
                                    &encoded_length,encoded,sizeof encoded)
  &&encoded_length==sizeof encoded;
 if(ok){memcpy(x,encoded+1,32);memcpy(y,encoded+33,32);}
 private_key_ready=ok;
 if(!ok)mbedtls_mpi_free(&private_key);
 mbedtls_ecp_point_free(&public_key);mbedtls_ecp_group_free(&group);
 memset(encoded,0,sizeof encoded);
 return ok;
}

bool pin_uv_derive_shared_secret(const uint8_t x[32],const uint8_t y[32],
                                uint8_t shared_secret[32]){
 if(!private_key_ready)return false;
 mbedtls_ecp_group group;mbedtls_ecp_point peer,shared;
 mbedtls_ecp_group_init(&group);mbedtls_ecp_point_init(&peer);mbedtls_ecp_point_init(&shared);
 uint8_t encoded[65],shared_encoded[65],secret[32];size_t shared_length=0;
 encoded[0]=4;memcpy(encoded+1,x,32);memcpy(encoded+33,y,32);
 bool ok=!mbedtls_ecp_group_load(&group,MBEDTLS_ECP_DP_SECP256R1)
  &&!mbedtls_ecp_point_read_binary(&group,&peer,encoded,sizeof encoded)
  &&!mbedtls_ecp_check_pubkey(&group,&peer)
  &&!mbedtls_ecp_mul(&group,&shared,&private_key,&peer,crypto_random,0)
  &&!mbedtls_ecp_point_write_binary(&group,&shared,MBEDTLS_ECP_PF_UNCOMPRESSED,
                                    &shared_length,shared_encoded,sizeof shared_encoded)
  &&shared_length==sizeof shared_encoded;
 if(ok)memcpy(secret,shared_encoded+1,sizeof secret);
 if(ok)mbedtls_sha256(secret,sizeof secret,shared_secret,0);
 mbedtls_mpi_free(&private_key);private_key_ready=false;
 mbedtls_ecp_point_free(&shared);mbedtls_ecp_point_free(&peer);mbedtls_ecp_group_free(&group);
 memset(encoded,0,sizeof encoded);memset(shared_encoded,0,sizeof shared_encoded);memset(secret,0,sizeof secret);
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
