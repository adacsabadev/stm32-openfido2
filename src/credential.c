#include "credential.h"
#include "stm32f4xx_hal.h"
#include "stm32f4xx_hal_flash_ex.h"
#include "mbedtls/ecdsa.h"
#include "mbedtls/sha256.h"
#include <string.h>
#include <stddef.h>
#include "ctaphid.h"
#include "log.h"

#define START 0x080e0000u
#define END 0x08100000u
#define SCRATCH_START 0x080a0000u
#define SCRATCH_HEADER 0x080bffe0u
#define SCRATCH_END 0x080c0000u
#define MAGIC 0x32444946u
#define TOMBSTONE_MAGIC 0x33444946u
#define RESIDENT_MAGIC 0x32525346u
#define COMMIT 0x434f4d54u
#define SNAPSHOT_MAGIC 0x31504d43u
#define SNAPSHOT_COMMIT 0x54494d43u
#define RESIDENT_SEQUENCE 0x80000000u
#define SLOT_COUNT ((END-START)/sizeof(credential))
#define SNAPSHOT_BYTES (SLOT_COUNT*sizeof(credential))
static uint32_t rng_previous;static bool rng_have;
typedef struct {
 uint32_t magic,sequence;
 uint8_t id[32],user_id[64];
 uint32_t user_id_len;
 uint8_t digest[32];
 uint32_t commit;
} resident_record;
typedef struct {
 uint32_t magic,crc,commit,reserved[5];
} snapshot_header;
_Static_assert(sizeof(credential)==144,"credential journal record size changed");
_Static_assert(sizeof(resident_record)==144,"resident journal record size changed");
_Static_assert(sizeof(snapshot_header)==32,"snapshot header size changed");
_Static_assert(SNAPSHOT_BYTES==131040u,"credential snapshot must fit sector 9");
static uint16_t listed_slots[SLOT_COUNT];
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

static bool record_valid(const credential*c){
 uint8_t hash[32];
 if((c->magic!=MAGIC&&c->magic!=TOMBSTONE_MAGIC)||c->commit!=COMMIT)return false;
 crypto_hash(c,offsetof(credential,digest),hash);
 bool ok=!memcmp(hash,c->digest,sizeof hash);memset(hash,0,sizeof hash);return ok;
}

static bool resident_valid(const resident_record*r){
 uint8_t hash[32];
 if(r->magic!=RESIDENT_MAGIC||r->commit!=COMMIT||!r->user_id_len||r->user_id_len>sizeof r->user_id)return false;
 crypto_hash(r,offsetof(resident_record,digest),hash);
 bool ok=!memcmp(hash,r->digest,sizeof hash);memset(hash,0,sizeof hash);return ok;
}

static bool blank_slot(uintptr_t address){
 const uint32_t*w=(const uint32_t*)address;
 for(size_t i=0;i<sizeof(credential)/4;i++)if(w[i]!=0xffffffffu)return false;
 return true;
}

static uintptr_t free_slot(void){
 for(uintptr_t p=START;p+sizeof(credential)<=END;p+=sizeof(credential))
  if(blank_slot(p))return p;
 return 0;
}

static bool latest_in_range(uintptr_t base,uint32_t count,uint32_t index,const credential*c){
 for(uint32_t i=index+1;i<count;i++){
  const credential*later=(const credential*)(base+(uintptr_t)i*sizeof(credential));
  if(record_valid(later)&&!memcmp(c->id,later->id,sizeof c->id)
   &&!memcmp(c->rp,later->rp,sizeof c->rp))return false;
 }
 return true;
}

static bool latest_record(uintptr_t address,const credential*c){
 uint32_t index=(uint32_t)((address-START)/sizeof(credential));
 return latest_in_range(START,SLOT_COUNT,index,c);
}

static void flash_log_hex(const char*label,uint32_t value){
 static const char digits[]="0123456789ABCDEF";
 char line[64];size_t used=0;
 while(*label&&used<sizeof line-13u)line[used++]=*label++;
 line[used++]='0';line[used++]='x';
 for(int shift=28;shift>=0;shift-=4)line[used++]=digits[(value>>shift)&15u];
 line[used++]='\r';line[used++]='\n';line[used]=0;log_puts(line);
}

static void flash_log_number(const char*label,uint32_t value){
 char line[64];size_t used=0;
 while(*label&&used<sizeof line-13u)line[used++]=*label++;
 char digits[10];size_t count=0;
 do{digits[count++]=(char)('0'+value%10u);value/=10u;}while(value);
 while(count)line[used++]=digits[--count];
 line[used++]='\r';line[used++]='\n';line[used]=0;log_puts(line);
}

static bool flash_erase_sector(uint32_t sector){
 flash_log_number("Flash erase begin sector=",sector);
 uint32_t address=sector==9?0x080a0000u:sector==10?0x080c0000u:
                  sector==11?0x080e0000u:0;
 if(address)flash_log_hex("Flash erase begin address=",address);
 HAL_StatusTypeDef ready=FLASH_WaitForLastOperation(50000u);
 if(ready!=HAL_OK){
  flash_log_number("Flash erase pre-wait status=",ready);
  flash_log_hex("Flash status register=",FLASH->SR);return false;
 }
 __HAL_FLASH_CLEAR_FLAG(FLASH_FLAG_EOP|FLASH_FLAG_OPERR|FLASH_FLAG_WRPERR|
                        FLASH_FLAG_PGAERR|FLASH_FLAG_PGPERR|FLASH_FLAG_PGSERR);
 CLEAR_BIT(FLASH->CR,FLASH_CR_PSIZE);
 SET_BIT(FLASH->CR,FLASH_PSIZE_WORD);
 MODIFY_REG(FLASH->CR,FLASH_CR_SNB,(sector<<3));
 SET_BIT(FLASH->CR,FLASH_CR_SER);
 SET_BIT(FLASH->CR,FLASH_CR_STRT);
 HAL_StatusTypeDef status=FLASH_WaitForLastOperation(50000u);
 CLEAR_BIT(FLASH->CR,FLASH_CR_SER|FLASH_CR_SNB);
 if(status!=HAL_OK){
  flash_log_number("Flash erase failed status=",status);
  flash_log_hex("Flash status register=",FLASH->SR);
  flash_log_hex("Flash control register=",FLASH->CR);return false;
 }
 flash_log_number("Flash erase complete sector=",sector);
 uint32_t cache=FLASH->ACR&(FLASH_ACR_ICEN|FLASH_ACR_DCEN);
 __HAL_FLASH_INSTRUCTION_CACHE_DISABLE();__HAL_FLASH_DATA_CACHE_DISABLE();
 __HAL_FLASH_INSTRUCTION_CACHE_RESET();__HAL_FLASH_DATA_CACHE_RESET();
 FLASH->ACR|=cache;
 return true;
}

static void append_hex32(char*line,size_t*used,uint32_t value){
 static const char digits[]="0123456789abcdef";
 for(int shift=28;shift>=0;shift-=4)line[(*used)++]=digits[(value>>shift)&15u];
}

static bool flash_write(uintptr_t address,const void*data,size_t length){
 if((address&3u)||(length&3u)){
  log_puts("Flash write rejected: unaligned address or length\r\n");return false;
 }
 flash_log_hex("Flash write begin address=",(uint32_t)address);
 flash_log_number("Flash write length=", (uint32_t)length);
 bool lock_when_done=(FLASH->CR&FLASH_CR_LOCK)!=RESET;
 if(lock_when_done&&HAL_FLASH_Unlock()!=HAL_OK){
  log_puts("Flash write failed: unlock error\r\n");
  flash_log_hex("Flash control register=",FLASH->CR);return false;
 }
 const uint8_t*bytes=data;bool ok=true;
 for(size_t offset=0;offset<length;offset+=4){
  uint32_t word;memcpy(&word,bytes+offset,sizeof word);
  HAL_StatusTypeDef status=HAL_FLASH_Program(
      FLASH_TYPEPROGRAM_WORD,(uint32_t)address+(uint32_t)offset,word);
  if(status!=HAL_OK){
   char line[80]="Flash program error at 0x";
   size_t used=strlen(line);
   uint32_t failed_address=(uint32_t)address+(uint32_t)offset;
   append_hex32(line,&used,failed_address);
   memcpy(line+used," status=",8);used+=8;
   line[used++]=(char)('0'+status);
   memcpy(line+used," sr=0x",6);used+=6;
   uint32_t sr=FLASH->SR;
   append_hex32(line,&used,sr);
   memcpy(line+used,"\r\n",2);used+=2;
   line[used]=0;
   log_puts(line);flash_log_hex("Flash control register=",FLASH->CR);
   flash_log_number("Flash words completed=", (uint32_t)(offset/4u));
   ok=false;break;
  }
 }
 if(lock_when_done)HAL_FLASH_Lock();
 if(ok)flash_log_number("Flash write complete bytes=", (uint32_t)length);
 return ok;
}

static uint32_t crc32_update(uint32_t crc,const uint8_t*data,size_t length){
 crc=~crc;
 for(size_t i=0;i<length;i++){
  crc^=data[i];
  for(unsigned bit=0;bit<8;bit++)crc=(crc>>1)^((crc&1u)?0xedb88320u:0u);
 }
 return ~crc;
}

static uint32_t journal_crc(uintptr_t base){
 uint32_t crc=0;
 for(uint32_t offset=0;offset<SNAPSHOT_BYTES;){
  size_t length=SNAPSHOT_BYTES-offset;
  if(length>256)length=256;
  crc=crc32_update(crc,(const uint8_t*)(base+offset),length);
  offset+=(uint32_t)length;
 }
 return crc;
}

static bool scratch_blank(void){
 for(uintptr_t p=SCRATCH_START;p<SCRATCH_END;p+=sizeof(uint32_t))
  if(*(const uint32_t*)p!=0xffffffffu)return false;
 return true;
}

static bool restore_snapshot(void){
 const snapshot_header*h=(const snapshot_header*)SCRATCH_HEADER;
 if(h->magic!=SNAPSHOT_MAGIC||h->commit!=SNAPSHOT_COMMIT){
  if(scratch_blank())return true;
  log_puts("Discarding incomplete credential snapshot\r\n");
  if(HAL_FLASH_Unlock()!=HAL_OK)return false;
  bool erased=flash_erase_sector(FLASH_SECTOR_9);
  HAL_FLASH_Lock();
  return erased;
 }
 if(journal_crc(SCRATCH_START)!=h->crc){log_puts("FATAL credential snapshot checksum mismatch\r\n");return false;}
 log_puts("Recovering credential journal after interrupted compaction\r\n");
 if(HAL_FLASH_Unlock()!=HAL_OK)return false;
 bool ok=flash_erase_sector(FLASH_SECTOR_11);
 if(ok)ok=flash_write(START,(const void*)SCRATCH_START,SNAPSHOT_BYTES);
 if(ok)ok=journal_crc(START)==h->crc;
 HAL_FLASH_Lock();
 if(!ok){log_puts("FATAL credential journal recovery failed\r\n");return false;}
 if(HAL_FLASH_Unlock()!=HAL_OK)return false;
 bool invalidated=HAL_FLASH_Program(FLASH_TYPEPROGRAM_WORD,SCRATCH_HEADER,0)==HAL_OK;
 bool erased=invalidated&&flash_erase_sector(FLASH_SECTOR_9);
 HAL_FLASH_Lock();
 if(!erased){log_puts("Credential journal recovered; scratch cleanup pending\r\n");return false;}
 log_puts("Credential journal recovery complete\r\n");return true;
}

bool credential_storage_init(void){return restore_snapshot();}

bool credential_room_for(uint32_t slots){
 uint32_t available=0;
 for(uintptr_t p=START;p+sizeof(credential)<=END;p+=sizeof(credential))
  if(blank_slot(p)&&++available>=slots)return true;
 return false;
}

bool credential_lookup(const uint8_t id[32],const uint8_t rp[32],credential*out){
 for(uintptr_t p=START;p+sizeof(credential)<=END;p+=sizeof(credential)){
  const credential*c=(const credential*)p;
  if(record_valid(c)&&latest_record(p,c)&&c->magic==MAGIC
   &&!memcmp(id,c->id,32)&&!memcmp(rp,c->rp,32)){*out=*c;return true;}
 }
 return false;
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

static const resident_record*resident_find_latest(const uint8_t id[32]){
 const resident_record*found=0;
 for(uintptr_t p=START;p+sizeof(credential)<=END;p+=sizeof(credential)){
  const resident_record*r=(const resident_record*)p;
  if(resident_valid(r)&&!memcmp(id,r->id,32))found=r;
 }
 return found;
}

bool credential_lookup_resident(const uint8_t rp[32],credential*out,
                                uint8_t user_id[64],uint32_t*user_id_len){
 bool found=false;uint8_t candidate_user_id[64];uint32_t candidate_user_id_len;
 for(uintptr_t p=START;p+sizeof(credential)<=END;p+=sizeof(credential)){
  const credential*c=(const credential*)p;
  if(record_valid(c)&&latest_record(p,c)&&c->magic==MAGIC&&!memcmp(rp,c->rp,32)
   &&resident_user_lookup(c->sequence,c->id,candidate_user_id,&candidate_user_id_len)){
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
  if(record_valid(c)&&latest_record(p,c))
   listed_slots[listed_count++]=(uint16_t)((p-START)/sizeof(credential));
 }
 return listed_count;
}

bool credential_list_get(uint32_t index,credential_summary*out){
 if(index>=listed_count)return false;
 const credential*c=(const credential*)(START+(uintptr_t)listed_slots[index]*sizeof(credential));
 if(!record_valid(c)||!latest_record((uintptr_t)c,c))return false;
 uint8_t user_id[64];uint32_t user_id_len;
 memcpy(out->id,c->id,sizeof out->id);memcpy(out->rp,c->rp,sizeof out->rp);
 out->counter=c->counter;out->deleted=c->magic==TOMBSTONE_MAGIC;
 out->discoverable=!out->deleted&&resident_user_lookup(c->sequence,c->id,user_id,&user_id_len);
 return true;
}

void credential_get_journal_stats(credential_journal_stats*out){
 memset(out,0,sizeof *out);
 for(uintptr_t p=START;p+sizeof(credential)<=END;p+=sizeof(credential)){
  if(blank_slot(p)){out->free_slots++;continue;}
  out->used_slots++;
  const credential*c=(const credential*)p;
  if(record_valid(c)&&latest_record(p,c)){
   if(c->magic==TOMBSTONE_MAGIC)out->deleted++;
   else out->active++;
  }
 }
}

static credential_result find_current(const uint8_t id_prefix[4],
                                      const uint8_t rp_prefix[4],
                                      bool deleted,credential*out,
                                      uintptr_t*address){
 uint32_t matches=0;
 credential selected={0};uintptr_t selected_address=0;
 for(uintptr_t p=START;p+sizeof(credential)<=END;p+=sizeof(credential)){
  const credential*c=(const credential*)p;
  if(record_valid(c)&&latest_record(p,c)&&
     (c->magic==TOMBSTONE_MAGIC)==deleted&&
     !memcmp(c->id,id_prefix,4)&&!memcmp(c->rp,rp_prefix,4)){
   selected=*c;selected_address=p;matches++;
  }
 }
 if(!matches)return CREDENTIAL_NOT_FOUND;
 if(matches>1)return CREDENTIAL_AMBIGUOUS;
 if(out)*out=selected;
 if(address)*address=selected_address;
 return CREDENTIAL_OK;
}

static credential_result append_record(credential*c,uint32_t magic){
 if(!credential_storage_init())return CREDENTIAL_FLASH_ERROR;
 uintptr_t address=free_slot();if(!address)return CREDENTIAL_NO_SPACE;
 c->magic=magic;
 uint32_t slot=(uint32_t)((address-START)/sizeof(credential));
 c->sequence=(c->sequence&RESIDENT_SEQUENCE)?c->sequence:slot;
 c->commit=COMMIT;crypto_hash(c,offsetof(credential,digest),c->digest);
 if(!flash_write(address,c,sizeof *c))return CREDENTIAL_FLASH_ERROR;
 return record_valid((const credential*)address)?CREDENTIAL_OK:CREDENTIAL_FLASH_ERROR;
}

bool credential_save(credential*c){return append_record(c,MAGIC)==CREDENTIAL_OK;}

static bool resident_save(const credential*c,const uint8_t*user_id,
                          uint32_t user_id_len,uint32_t*slot_out){
 uintptr_t address=free_slot();if(!address||!user_id_len||user_id_len>64)return false;
 resident_record record={0};record.magic=RESIDENT_MAGIC;
 record.sequence=(uint32_t)((address-START)/sizeof(credential));
 memcpy(record.id,c->id,sizeof record.id);memcpy(record.user_id,user_id,user_id_len);
 record.user_id_len=user_id_len;record.commit=COMMIT;
 crypto_hash(&record,offsetof(resident_record,digest),record.digest);
 if(!flash_write(address,&record,sizeof record)||!resident_valid((const resident_record*)address))return false;
 *slot_out=record.sequence;return true;
}

bool credential_save_resident(credential*c,const uint8_t*user_id,uint32_t user_id_len){
 if(!credential_storage_init())return false;
 if(!credential_room_for(2))return false;
 uint32_t user_slot;
 if(!resident_save(c,user_id,user_id_len,&user_slot))return false;
 c->sequence=RESIDENT_SEQUENCE|user_slot;
 return credential_save(c);
}

credential_result credential_delete(const uint8_t id_prefix[4],const uint8_t rp_prefix[4]){
 if(!credential_storage_init())return CREDENTIAL_FLASH_ERROR;
 credential current;credential_result result=find_current(id_prefix,rp_prefix,false,&current,0);
 if(result!=CREDENTIAL_OK)return result;
 current.sequence=0;return append_record(&current,TOMBSTONE_MAGIC);
}

credential_result credential_undelete(const uint8_t id_prefix[4],const uint8_t rp_prefix[4]){
 if(!credential_storage_init())return CREDENTIAL_FLASH_ERROR;
 credential tombstone;uintptr_t tomb_address;
 credential_result result=find_current(id_prefix,rp_prefix,true,&tombstone,&tomb_address);
 if(result!=CREDENTIAL_OK)return result;
 const credential*previous=0;
 for(uintptr_t p=START;p<tomb_address;p+=sizeof(credential)){
  const credential*c=(const credential*)p;
  if(record_valid(c)&&c->magic==MAGIC&&!memcmp(c->id,tombstone.id,32)
   &&!memcmp(c->rp,tombstone.rp,32))previous=c;
 }
 if(!previous)return CREDENTIAL_NOT_FOUND;
 credential restored=*previous;
 return append_record(&restored,MAGIC);
}

credential_result credential_set_discoverable(const uint8_t id_prefix[4],
                                              const uint8_t rp_prefix[4],bool enabled){
 if(!credential_storage_init())return CREDENTIAL_FLASH_ERROR;
 credential current;
 credential_result result=find_current(id_prefix,rp_prefix,false,&current,0);
 if(result!=CREDENTIAL_OK)return result;
 uint8_t user_id[64];uint32_t user_id_len;
 bool discoverable=resident_user_lookup(current.sequence,current.id,user_id,&user_id_len);
 if(discoverable==enabled)return CREDENTIAL_OK;
 if(!enabled){current.sequence=0;return append_record(&current,MAGIC);}
 const resident_record*resident=resident_find_latest(current.id);
 if(!resident)return CREDENTIAL_NO_USER_HANDLE;
 if(!credential_room_for(2))return CREDENTIAL_NO_SPACE;
 uint32_t user_slot;
 if(!resident_save(&current,resident->user_id,resident->user_id_len,&user_slot))
  return CREDENTIAL_FLASH_ERROR;
 current.sequence=RESIDENT_SEQUENCE|user_slot;
 return append_record(&current,MAGIC);
}

static bool compact_write_credential(uintptr_t address,credential*c){
 c->commit=COMMIT;crypto_hash(c,offsetof(credential,digest),c->digest);
 return flash_write(address,c,sizeof *c)&&record_valid((const credential*)address);
}

static bool compact_write_resident(uintptr_t address,resident_record*r){
 r->commit=COMMIT;crypto_hash(r,offsetof(resident_record,digest),r->digest);
 return flash_write(address,r,sizeof *r)&&resident_valid((const resident_record*)address);
}

static bool compacted_journal(void){
 uint32_t destination=0;
 for(uint32_t i=0;i<SLOT_COUNT;i++){
  const credential*source=(const credential*)(SCRATCH_START+(uintptr_t)i*sizeof(credential));
  if(!record_valid(source)||source->magic!=MAGIC||
     !latest_in_range(SCRATCH_START,SLOT_COUNT,i,source))continue;
  credential current=*source;
  bool discoverable=(current.sequence&RESIDENT_SEQUENCE)!=0;
  const resident_record*latest_resident=0;
  for(uint32_t j=0;j<SLOT_COUNT;j++){
   const resident_record*r=(const resident_record*)(SCRATCH_START+(uintptr_t)j*sizeof(credential));
   if(resident_valid(r)&&!memcmp(current.id,r->id,32))latest_resident=r;
  }
  if(latest_resident){
   if(destination>=SLOT_COUNT)return false;
   resident_record copy=*latest_resident;
   copy.sequence=destination;
   if(!compact_write_resident(START+(uintptr_t)destination*sizeof(credential),&copy))return false;
   current.sequence=(discoverable?RESIDENT_SEQUENCE:0)|destination++;
  }else current.sequence=destination;
  if(destination>=SLOT_COUNT)return false;
  if(!compact_write_credential(START+(uintptr_t)destination*sizeof(credential),&current))return false;
  destination++;
 }
 return true;
}

bool credential_compact(void){
 if(!credential_storage_init()){
  log_puts("Compaction stopped: pending journal recovery failed\r\n");return false;
 }
 if(HAL_FLASH_Unlock()!=HAL_OK){
  log_puts("Compaction stopped: flash unlock failed\r\n");return false;
 }
 bool ok=flash_erase_sector(FLASH_SECTOR_9);
 if(!ok)log_puts("Compaction failed: could not erase sector 9 snapshot area\r\n");
 if(ok&&!flash_write(SCRATCH_START,(const void*)START,SNAPSHOT_BYTES)){
  ok=false;log_puts("Compaction failed: snapshot programming failed\r\n");
 }
 uint32_t crc=ok?journal_crc(SCRATCH_START):0;
 if(ok&&journal_crc(START)!=crc){
  ok=false;log_puts("Compaction failed: snapshot checksum mismatch\r\n");
 }
 if(ok){
  const uint32_t header[3]={SNAPSHOT_MAGIC,crc,SNAPSHOT_COMMIT};
  flash_log_hex("Flash snapshot commit address=",SCRATCH_HEADER);
  ok=flash_write(SCRATCH_HEADER,header,sizeof header);
  if(!ok)log_puts("Compaction failed: could not commit recovery snapshot\r\n");
 }
 HAL_FLASH_Lock();
 if(!ok)return false;
 if(HAL_FLASH_Unlock()!=HAL_OK){
  log_puts("Compaction stopped: flash unlock failed before journal erase\r\n");return false;
 }
 ok=flash_erase_sector(FLASH_SECTOR_11);
 HAL_FLASH_Lock();
 if(!ok){log_puts("Compaction failed: could not erase credential sector 11\r\n");return false;}
 if(!compacted_journal()){
  log_puts("Compaction failed: writing compacted journal failed; snapshot retained\r\n");return false;
 }
 if(HAL_FLASH_Unlock()!=HAL_OK){
  log_puts("Compaction stopped: flash unlock failed before snapshot cleanup\r\n");return false;
 }
 flash_log_hex("Flash snapshot invalidate address=",SCRATCH_HEADER);
 HAL_StatusTypeDef invalidate_status=HAL_FLASH_Program(
     FLASH_TYPEPROGRAM_WORD,SCRATCH_HEADER,0);
 bool invalidated=invalidate_status==HAL_OK;
 if(!invalidated){
  flash_log_number("Flash snapshot invalidate status=",invalidate_status);
  flash_log_hex("Flash status register=",FLASH->SR);
 }
 if(!invalidated)log_puts("Compaction failed: could not invalidate recovery marker\r\n");
 bool cleaned=invalidated&&flash_erase_sector(FLASH_SECTOR_9);
 HAL_FLASH_Lock();
 if(invalidated&&!cleaned)log_puts("Compaction finished, but sector 9 cleanup failed\r\n");
 if(cleaned)log_puts("Credential journal compaction complete\r\n");
 return cleaned;
}

bool credential_erase_all(void){
 if(!credential_storage_init())return false;
 if(HAL_FLASH_Unlock()!=HAL_OK)return false;
 bool ok=flash_erase_sector(FLASH_SECTOR_11);
 HAL_FLASH_Lock();listed_count=0;return ok;
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
