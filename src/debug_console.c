#include "debug_console.h"
#include "credential.h"
#include "log.h"
#include "pin_uv.h"
#include "platform.h"
#include "usb_composite.h"
#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#define COMMAND_CAP 160u
#define TX_LOW_WATER 256u

static char command[COMMAND_CAP];
static uint32_t command_length;
static bool discarding,listing;
static uint32_t list_index,list_count;

static void append_text(char*out,uint32_t*used,const char*text){
 while(*text)out[(*used)++]=*text++;
}

static void append_u32(char*out,uint32_t*used,uint32_t value){
 char digits[10];uint32_t count=0;
 do{digits[count++]=(char)('0'+value%10u);value/=10u;}while(value);
 while(count)out[(*used)++]=digits[--count];
}

static void append_hex(char*out,uint32_t*used,const uint8_t*value,uint32_t length){
 static const char digits[]="0123456789abcdef";
 for(uint32_t i=0;i<length;i++){
  out[(*used)++]=digits[value[i]>>4];out[(*used)++]=digits[value[i]&15u];
 }
}

static void append_hex32(char*out,uint32_t*used,uint32_t value){
 static const char digits[]="0123456789abcdef";
 for(int shift=28;shift>=0;shift-=4)out[(*used)++]=digits[(value>>shift)&15u];
}

static uint32_t read_le32(const uint8_t*bytes){
 return (uint32_t)bytes[0]|((uint32_t)bytes[1]<<8)|
        ((uint32_t)bytes[2]<<16)|((uint32_t)bytes[3]<<24);
}

static void print_dump_raw_record(const char*label,uint32_t address,
                                  const uint8_t*record){
 char line[80];uint32_t used;
 log_puts(label);log_puts(" address=0x");
 used=0;append_hex32(line,&used,address);line[used]=0;log_puts(line);log_puts("\r\n");
 for(uint32_t offset=0;offset<144;offset+=16){
  used=0;append_hex32(line,&used,address+offset);
  append_text(line,&used," +");append_hex32(line,&used,offset);
  append_text(line,&used,": ");
  append_hex(line,&used,record+offset,16);append_text(line,&used,"\r\n");
  line[used]=0;log_puts(line);
 }
}

static void print_dump_raw(const credential_dump*dump){
 print_dump_raw_record("Credential record",dump->address,dump->record);
 if(dump->has_resident)
  print_dump_raw_record("Resident record",dump->resident_address,dump->resident_record);
 else log_puts("Resident record: none found\r\n");
}

static void print_dump_field(const char*label,const uint8_t*data,uint32_t length){
 char line[160];uint32_t used=0;
 append_text(line,&used,label);append_hex(line,&used,data,length);
 line[used]=0;log_puts(line);log_puts("\r\n");
}

static void print_dump_formatted(const credential_dump*dump){
 const uint8_t*record=dump->record;
 uint32_t magic=read_le32(record),sequence=read_le32(record+4);
 log_puts("Credential record at 0x");
 char line[80];uint32_t used=0;append_hex32(line,&used,dump->address);
 line[used]=0;log_puts(line);log_puts("\r\n");
 log_puts(magic==0x32444946u?" type=active\r\n":
          magic==0x33444946u?" type=deleted tombstone\r\n":" type=invalid\r\n");
 used=0;append_text(line,&used,"sequence=0x");append_hex32(line,&used,sequence);
 append_text(line,&used,(sequence&0x80000000u)?" (resident-linked)\r\n":" (ordinary)\r\n");
 line[used]=0;log_puts(line);
 print_dump_field("credential_id=",record+8,32);
 print_dump_field("rp_id_sha256=",record+40,32);
 print_dump_field("private_scalar=",record+72,32);
 used=0;append_text(line,&used,"counter=");append_u32(line,&used,read_le32(record+104));
 append_text(line,&used," digest_valid=");
 append_text(line,&used,dump->record_valid?"yes\r\n":"no\r\n");
 line[used]=0;log_puts(line);
 print_dump_field("stored_record_digest=",record+108,32);
 used=0;append_text(line,&used,"commit=0x");append_hex32(line,&used,read_le32(record+140));
 append_text(line,&used,"\r\n");line[used]=0;log_puts(line);
 if(!dump->has_resident){log_puts("resident_record=none found\r\n");return;}
 const uint8_t*resident=dump->resident_record;
 used=0;append_text(line,&used,"resident_record_address=0x");
 append_hex32(line,&used,dump->resident_address);append_text(line,&used,"\r\n");
 line[used]=0;log_puts(line);
 used=0;append_text(line,&used,"resident_magic=0x");
 append_hex32(line,&used,read_le32(resident));append_text(line,&used," sequence=");
 append_u32(line,&used,read_le32(resident+4));append_text(line,&used,"\r\n");
 line[used]=0;log_puts(line);
 uint32_t user_id_len=read_le32(resident+104);
 used=0;append_text(line,&used,"user_id_length=");append_u32(line,&used,user_id_len);
 append_text(line,&used," resident_digest_valid=");
 append_text(line,&used,dump->resident_valid?"yes\r\n":"no\r\n");
 line[used]=0;log_puts(line);
 if(user_id_len<=64)print_dump_field("user_handle=",resident+40,user_id_len);
 else log_puts("user_handle=invalid length\r\n");
 print_dump_field("stored_resident_digest=",resident+108,32);
 used=0;append_text(line,&used,"resident_commit=0x");
 append_hex32(line,&used,read_le32(resident+140));append_text(line,&used,"\r\n");
 line[used]=0;log_puts(line);
}

static void print_key(uint32_t index){
 credential_summary key;char line[112];uint32_t used=0;
 if(!credential_list_get(index,&key))return;
 append_text(line,&used,"key id=");append_hex(line,&used,key.id,4);
 append_text(line,&used," rp=");append_hex(line,&used,key.rp,4);
 append_text(line,&used,key.deleted?" state=deleted":" state=active");
 append_text(line,&used," counter=");append_u32(line,&used,key.counter);
 if(!key.deleted)append_text(line,&used,key.discoverable?" discoverable=yes\r\n":" discoverable=no\r\n");
 else append_text(line,&used,"\r\n");
 line[used]=0;log_puts(line);
}

static int hex_value(char c){
 if(c>='0'&&c<='9')return c-'0';
 if(c>='a'&&c<='f')return c-'a'+10;
 if(c>='A'&&c<='F')return c-'A'+10;
 return -1;
}

static bool parse_hex4(const char*text,uint8_t bytes[4]){
 for(uint32_t i=0;i<4;i++){
  int high=hex_value(text[i*2]),low=hex_value(text[i*2+1]);
  if(high<0||low<0)return false;
  bytes[i]=(uint8_t)((high<<4)|low);
 }
 return true;
}

static bool parse_selector(const char*text,uint8_t id[4],uint8_t rp[4],
                           const char**tail){
 if(strlen(text)<17||text[8]!=' '||!parse_hex4(text,id)||!parse_hex4(text+9,rp))return false;
 if(text[17]&&text[17]!=' ')return false;
 *tail=text+17;
 return true;
}

static void report_credential_result(credential_result result){
 switch(result){
 case CREDENTIAL_OK:log_puts("OK\r\n");break;
 case CREDENTIAL_NOT_FOUND:log_puts("ERR matching credential state not found\r\n");break;
 case CREDENTIAL_AMBIGUOUS:log_puts("ERR fingerprint pair is ambiguous; use distinct fingerprints\r\n");break;
 case CREDENTIAL_NO_USER_HANDLE:log_puts("ERR no stored user handle; re-enroll to enable discoverability\r\n");break;
 case CREDENTIAL_NO_SPACE:log_puts("ERR journal has insufficient free slots; run keys compact confirm\r\n");break;
 case CREDENTIAL_FLASH_ERROR:log_puts("ERR flash operation failed\r\n");break;
 }
}

static bool valid_pin(const char*pin,size_t length){
 if(length<4||length>63)return false;
 for(size_t i=0;i<length;i++)if(pin[i]<'0'||pin[i]>'9')return false;
 return true;
}

static const char*command_name(const char*text){
 if(!strcmp(text,"help"))return "help";
 if(!strcmp(text,"status"))return "status";
 if(!strcmp(text,"keys list"))return "keys list";
 if(!strncmp(text,"keys dump raw ",14))return "keys dump raw";
 if(!strncmp(text,"keys dump formatted ",20))return "keys dump formatted";
 if(!strcmp(text,"keys erase-all confirm"))return "keys erase-all";
 if(!strcmp(text,"keys compact confirm"))return "keys compact";
 if(!strcmp(text,"pin status"))return "pin status";
 if(!strcmp(text,"pin delete confirm"))return "pin delete";
 if(!strncmp(text,"keys delete ",12))return "keys delete";
 if(!strncmp(text,"keys undelete ",14))return "keys undelete";
 if(!strncmp(text,"keys discoverable ",18))return "keys discoverable";
 if(!strncmp(text,"pin set ",8))return "pin set";
 if(!strncmp(text,"pin change ",11))return "pin change";
 return "unsupported";
}

static void execute_command(void){
 command[command_length]=0;
 listing=false;
 if(!command_length)return;
 const char*name=command_name(command);
 log_puts("Console command begin: ");log_puts(name);log_puts("\r\n");
 if(!strcmp(command,"help")){
  log_puts("help\r\nstatus\r\nkeys list\r\n");
  log_puts("keys delete <id8> <rp8>\r\nkeys undelete <id8> <rp8>\r\n");
  log_puts("keys discoverable <id8> <rp8> on|off\r\n");
  log_puts("keys dump raw <id8> <rp8>\r\nkeys dump formatted <id8> <rp8>\r\n");
  log_puts("keys dump raw <id8> <rp8>\r\n");
  log_puts("keys dump formatted <id8> <rp8>\r\n");
  log_puts("keys erase-all confirm\r\nkeys compact confirm\r\n");
  log_puts("pin status\r\npin set <4-63 digits>\r\n");
  log_puts("pin change <old> <new>\r\npin delete confirm\r\n");
 }else if(!strcmp(command,"pin status")){
  log_puts(pin_uv_configured()?"PIN is configured\r\n":"PIN is not configured\r\n");
 }else if(command_length>=8&&!memcmp(command,"pin set ",8)){
  size_t length=command_length-8;
  if(!valid_pin(command+8,length))log_puts("ERR PIN must contain 4-63 ASCII digits\r\n");
  else if(pin_uv_configured())log_puts("ERR PIN already set; use pin change <old> <new>\r\n");
  else if(pin_uv_set_from_console((const uint8_t*)command+8,length))log_puts("PIN verifier stored\r\n");
  else log_puts("ERR PIN verifier could not be stored\r\n");
 }else if(command_length>11&&!memcmp(command,"pin change ",11)){
  char*old_pin=command+11;char*separator=strchr(old_pin,' ');
  if(!separator||strchr(separator+1,' '))log_puts("ERR use pin change <old> <new>\r\n");
  else{
   size_t old_length=(size_t)(separator-old_pin),new_length=strlen(separator+1);
   *separator=0;
   if(!valid_pin(old_pin,old_length)||!valid_pin(separator+1,new_length))
    log_puts("ERR old and new PINs must each contain 4-63 ASCII digits\r\n");
   else if(!pin_uv_configured())log_puts("ERR PIN is not configured; use pin set <new>\r\n");
   else if(pin_uv_change_from_console((const uint8_t*)old_pin,old_length,
                                     (const uint8_t*)separator+1,new_length))
    log_puts("PIN updated\r\n");
   else log_puts("ERR old PIN incorrect or new PIN could not be stored\r\n");
  }
 }else if(!strcmp(command,"pin delete confirm")){
  if(!pin_uv_configured())log_puts("PIN is not configured\r\n");
  else if(pin_uv_delete())log_puts("PIN deleted\r\n");
  else log_puts("ERR PIN erase failed\r\n");
 }else if(!strcmp(command,"status")){
  credential_journal_stats stats;credential_get_journal_stats(&stats);
  char line[192];uint32_t used=0;
  append_text(line,&used,"uptime_ms=");append_u32(line,&used,platform_millis());
  append_text(line,&used," keys_active=");append_u32(line,&used,stats.active);
  append_text(line,&used," keys_deleted=");append_u32(line,&used,stats.deleted);
  append_text(line,&used," journal_used_slots=");append_u32(line,&used,stats.used_slots);
  append_text(line,&used," journal_free_slots=");append_u32(line,&used,stats.free_slots);
  append_text(line,&used," cdc_rx_dropped=");append_u32(line,&used,usb_cdc_rx_dropped());
  append_text(line,&used," cdc_tx_dropped=");append_u32(line,&used,usb_cdc_tx_dropped());
  append_text(line,&used,"\r\n");line[used]=0;log_puts(line);
 }else if(!strcmp(command,"keys list")){
  list_index=0;list_count=credential_list_count();listing=true;
  if(!list_count){log_puts("No credential records\r\n");listing=false;}
  else{
   char line[72];uint32_t used=0;
   append_text(line,&used,"Credential records: ");append_u32(line,&used,list_count);
   append_text(line,&used,"; id/rp are 4-byte fingerprints\r\n");
   line[used]=0;log_puts(line);
  }
 }else if(command_length>20&&!memcmp(command,"keys dump formatted ",20)){
  uint8_t id[4],rp[4];const char*tail;
  if(!parse_selector(command+20,id,rp,&tail)||*tail)
   log_puts("ERR use keys dump formatted <id8> <rp8>\r\n");
  else{
   credential_dump dump;credential_result result=credential_dump_lookup(id,rp,&dump);
   if(result!=CREDENTIAL_OK)report_credential_result(result);
   else print_dump_formatted(&dump);
  }
 }else if(command_length>14&&!memcmp(command,"keys dump raw ",14)){
  uint8_t id[4],rp[4];const char*tail;
  if(!parse_selector(command+14,id,rp,&tail)||*tail)
   log_puts("ERR use keys dump raw <id8> <rp8>\r\n");
  else{
   credential_dump dump;credential_result result=credential_dump_lookup(id,rp,&dump);
   if(result!=CREDENTIAL_OK)report_credential_result(result);
   else print_dump_raw(&dump);
  }
 }else if(!strcmp(command,"keys erase-all confirm")){
  if(credential_erase_all())log_puts("All credentials erased; PIN unchanged\r\n");
  else log_puts("ERR credential-sector erase failed\r\n");
 }else if(!strcmp(command,"keys compact confirm")){
  if(credential_compact())log_puts("Credential journal compacted\r\n");
  else log_puts("ERR compaction failed; recovery snapshot retained if needed; reboot and check status\r\n");
 }else if(command_length>12&&!memcmp(command,"keys delete ",12)){
  uint8_t id[4],rp[4];const char*tail;
  if(!parse_selector(command+12,id,rp,&tail)||*tail)log_puts("ERR use keys delete <id8> <rp8>\r\n");
  else report_credential_result(credential_delete(id,rp));
 }else if(command_length>14&&!memcmp(command,"keys undelete ",14)){
  uint8_t id[4],rp[4];const char*tail;
  if(!parse_selector(command+14,id,rp,&tail)||*tail)log_puts("ERR use keys undelete <id8> <rp8>\r\n");
  else report_credential_result(credential_undelete(id,rp));
 }else if(command_length>18&&!memcmp(command,"keys discoverable ",18)){
  uint8_t id[4],rp[4];const char*tail;
  if(!parse_selector(command+18,id,rp,&tail)||
     (strcmp(tail," on")&&strcmp(tail," off")))
   log_puts("ERR use keys discoverable <id8> <rp8> on|off\r\n");
  else report_credential_result(credential_set_discoverable(id,rp,!strcmp(tail," on")));
 }else{
  log_puts("ERR unsupported command; send help\r\n");
 }
 log_puts("Console command end: ");log_puts(name);log_puts("\r\n");
 memset(command,0,sizeof command);
 command_length=0;
}

void debug_console_poll(void){
 uint8_t byte;
 while(usb_cdc_read(&byte)){
  if(byte=='\r')continue;
  if(byte=='\n'){
   if(discarding)log_puts("ERR command too long; discarded\r\n");
   else execute_command();
   discarding=false;command_length=0;
  }else if(!discarding){
   if(command_length+1u>=COMMAND_CAP)discarding=true;
   else command[command_length++]=(char)byte;
  }
 }
 if(listing&&usb_cdc_pending()<TX_LOW_WATER){
  if(list_index<list_count)print_key(list_index++);
  else{log_puts("End of credential list\r\n");listing=false;}
 }
}
