#include "credential.h"
#include "stm32f4xx_hal.h"
#include "mbedtls/ecdsa.h"
#include "mbedtls/sha256.h"
#include <string.h>
#include <stddef.h>
#include "ctaphid.h"
#define START 0x080e0000u
#define END 0x08100000u
#define MAGIC 0x32444946u
#define RESIDENT_MAGIC 0x32525346u
#define COMMIT 0x434f4d54u
#define RESIDENT_SEQUENCE 0x80000000u
#define SLOT_COUNT ((END-START)/sizeof(credential))
static uint32_t rng_previous;static bool rng_have;
typedef struct {
 uint32_t magic,sequence;
 uint8_t id[32],user_id[64];
 uint32_t user_id_len;
 uint8_t digest[32];
 uint32_t commit;
} resident_record;
_Static_assert(sizeof(credential)==144,"credential journal record size changed");
_Static_assert(sizeof(resident_record)==144,"resident journal record size changed");
static uint16_t listed_slots[(END-START)/sizeof(credential)];
static uint32_t listed_count;
void crypto_hash(const void*p,size_t n,uint8_t out[32]){mbedtls_sha256(p,n,out,0);}
int crypto_random(void*ctx,uint8_t*out,size_t n){
 ctaphid_processing_tick();
 (void)ctx;__HAL_RCC_RNG_CLK_ENABLE();RNG->CR|=RNG_CR_RNGEN;
 while(n){uint32_t start=HAL_GetTick();while(!(RNG->SR&RNG_SR_DRDY)){if((RNG->SR&(RNG_SR_CECS|RNG_SR_SECS))||(uint32_t)(HAL_GetTick()-start)>100)return -1;}
  if(RNG->SR&(RNG_SR_CECS|RNG_SR_SECS))return -1;
  uint32_t word=RNG->DR;
  if(rng_have&&word==rng_previous)return -1;
  rng_previous=word;rng_have=true;
  size_t count=n<4?n:4;memcpy(out,&word,count);out+=count;n-=count;
 }return 0;
}
static bool valid(const credential*c){uint8_t hash[32];if(c->magic!=MAGIC||c->commit!=COMMIT)return false;crypto_hash(c,offsetof(credential,digest),hash);return !memcmp(hash,c->digest,32);}
static bool resident_valid(const resident_record*r){
 uint8_t hash[32];
 if(r->magic!=RESIDENT_MAGIC||r->commit!=COMMIT||!r->user_id_len||r->user_id_len>sizeof r->user_id)return false;
 crypto_hash(r,offsetof(resident_record,digest),hash);
 return !memcmp(hash,r->digest,32);
}
static uintptr_t free_slot(void){
 for(uintptr_t p=START;p+sizeof(credential)<=END;p+=sizeof(credential)){
  const uint32_t*w=(const uint32_t*)p;bool blank=true;
  for(size_t i=0;i<sizeof(credential)/4;i++)if(w[i]!=0xffffffffu){blank=false;break;}
  if(blank)return p;
 }return 0;
}
static bool latest_record(uintptr_t address,const credential*c){
 for(uintptr_t p=address+sizeof(credential);p+sizeof(credential)<=END;p+=sizeof(credential)){
  const credential*later=(const credential*)p;
  if(valid(later)&&!memcmp(c->id,later->id,32)&&!memcmp(c->rp,later->rp,32))return false;
 }
 return true;
}
bool credential_room_for(uint32_t slots){
 uint32_t available=0;
 for(uintptr_t p=START;p+sizeof(credential)<=END;p+=sizeof(credential)){
  const uint32_t*w=(const uint32_t*)p;bool blank=true;
  for(size_t i=0;i<sizeof(credential)/4;i++)if(w[i]!=0xffffffffu){blank=false;break;}
  if(blank&&++available>=slots)return true;
 }
 return false;
}
bool credential_lookup(const uint8_t id[32],const uint8_t rp[32],credential*out){
 bool found=false;for(uintptr_t p=START;p+sizeof(credential)<=END;p+=sizeof(credential)){
  const credential*c=(const credential*)p;
  if(valid(c)&&!memcmp(id,c->id,32)&&!memcmp(rp,c->rp,32)){*out=*c;found=true;}
 }return found;
}
static bool resident_user_lookup(uint32_t sequence,const uint8_t id[32],
                                 uint8_t user_id[64],uint32_t*user_id_len){
 if(!(sequence&RESIDENT_SEQUENCE))return false;
 uint32_t slot=sequence&~RESIDENT_SEQUENCE;
 if(slot>=SLOT_COUNT)return false;
 const resident_record*r=(const resident_record*)(START+(uintptr_t)slot*sizeof(resident_record));
 if(!resident_valid(r)||memcmp(id,r->id,32))return false;
 memcpy(user_id,r->user_id,r->user_id_len);*user_id_len=r->user_id_len;return true;
}
bool credential_lookup_resident(const uint8_t rp[32],credential*out,
                                uint8_t user_id[64],uint32_t*user_id_len){
 bool found=false;uint8_t candidate_user_id[64];uint32_t candidate_user_id_len;
 for(uintptr_t p=START;p+sizeof(credential)<=END;p+=sizeof(credential)){
  const credential*c=(const credential*)p;
  if(valid(c)&&!memcmp(rp,c->rp,32)&&resident_user_lookup(c->sequence,c->id,candidate_user_id,&candidate_user_id_len)){
   *out=*c;memcpy(user_id,candidate_user_id,candidate_user_id_len);
   *user_id_len=candidate_user_id_len;found=true;
  }
 }
 return found;
}
uint32_t credential_list_count(void){
 listed_count=0;
 for(uintptr_t p=START;p+sizeof(credential)<=END;p+=sizeof(credential)){
  const credential*c=(const credential*)p;
  if(valid(c)&&latest_record(p,c))
   listed_slots[listed_count++]=(uint16_t)((p-START)/sizeof(credential));
 }
 return listed_count;
}
bool credential_list_get(uint32_t index,credential_summary*out){
 if(index>=listed_count)return false;
 const credential*c=(const credential*)(START+(uintptr_t)listed_slots[index]*sizeof(credential));
 if(!valid(c))return false;
 uint8_t user_id[64];uint32_t user_id_len;
 memcpy(out->id,c->id,sizeof out->id);memcpy(out->rp,c->rp,sizeof out->rp);
 out->counter=c->counter;
 out->discoverable=resident_user_lookup(c->sequence,c->id,user_id,&user_id_len);
 return true;
}
static bool resident_save(const credential*c,const uint8_t*user_id,uint32_t user_id_len,uint32_t*slot_out){
 uintptr_t address=free_slot();if(!address||!user_id_len||user_id_len>64)return false;
 resident_record record={0};record.magic=RESIDENT_MAGIC;
 record.sequence=(uint32_t)((address-START)/sizeof(credential));
 memcpy(record.id,c->id,sizeof record.id);memcpy(record.user_id,user_id,user_id_len);
 record.user_id_len=user_id_len;record.commit=COMMIT;
 crypto_hash(&record,offsetof(resident_record,digest),record.digest);
 if(HAL_FLASH_Unlock()!=HAL_OK)return false;
 const uint32_t*words=(const uint32_t*)&record;bool ok=true;
 for(size_t i=0;i<sizeof(record)/4;i++){
  if(HAL_FLASH_Program(FLASH_TYPEPROGRAM_WORD,(uint32_t)address+(uint32_t)i*4,words[i])!=HAL_OK){ok=false;break;}
 }
 HAL_FLASH_Lock();if(!ok||!resident_valid((const resident_record*)address))return false;
 *slot_out=record.sequence;return true;
}
bool credential_save(credential*c){
 uintptr_t address=free_slot();if(!address)return false;
 c->magic=MAGIC;
 if(!(c->sequence&RESIDENT_SEQUENCE))c->sequence=(uint32_t)((address-START)/sizeof(credential));
 c->commit=COMMIT;
 crypto_hash(c,offsetof(credential,digest),c->digest);
 /* Append only: no sector erasure, commit word written last. */
 if(HAL_FLASH_Unlock()!=HAL_OK)return false;
 const uint32_t*words=(const uint32_t*)c;bool ok=true;
 for(size_t i=0;i<sizeof(*c)/4;i++){
  if(HAL_FLASH_Program(FLASH_TYPEPROGRAM_WORD,(uint32_t)address+(uint32_t)i*4,words[i])!=HAL_OK){ok=false;break;}
 }
 HAL_FLASH_Lock();return ok&&valid((const credential*)address);
}
bool credential_save_resident(credential*c,const uint8_t*user_id,uint32_t user_id_len){
 if(!credential_room_for(2))return false;
 uint32_t user_slot;
 if(!resident_save(c,user_id,user_id_len,&user_slot))return false;
 c->sequence=RESIDENT_SEQUENCE|user_slot;
 return credential_save(c);
}
bool crypto_generate(credential*c,uint8_t x[32],uint8_t y[32]){
 mbedtls_ecdsa_context key;mbedtls_ecdsa_init(&key);
 bool ok=mbedtls_ecdsa_genkey(&key,MBEDTLS_ECP_DP_SECP256R1,crypto_random,0)==0;
 if(ok)ok=!mbedtls_mpi_write_binary(&key.d,c->secret,32)&&!mbedtls_mpi_write_binary(&key.Q.X,x,32)&&!mbedtls_mpi_write_binary(&key.Q.Y,y,32);
 mbedtls_ecdsa_free(&key);return ok;
}
bool crypto_sign(const credential*c,const uint8_t*data,size_t n,uint8_t sig[80],size_t*len){
 uint8_t hash[32];crypto_hash(data,n,hash);mbedtls_ecdsa_context key;mbedtls_ecdsa_init(&key);
 bool ok=!mbedtls_ecp_group_load(&key.grp,MBEDTLS_ECP_DP_SECP256R1)&&!mbedtls_mpi_read_binary(&key.d,c->secret,32);
 if(ok)ok=!mbedtls_ecdsa_write_signature(&key,MBEDTLS_MD_SHA256,hash,32,sig,len,crypto_random,0);
 mbedtls_ecdsa_free(&key);memset(hash,0,sizeof hash);return ok;
}
