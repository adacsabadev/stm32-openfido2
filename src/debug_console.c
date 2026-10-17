#include "debug_console.h"
#include "credential.h"
#include "log.h"
#include "pin_uv.h"
#include "platform.h"
#include "usb_composite.h"
#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#define COMMAND_CAP 80u
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

static void print_key(uint32_t index){
 credential_summary key;char line[96];uint32_t used=0;
 if(!credential_list_get(index,&key))return;
 append_text(line,&used,"key id=");append_hex(line,&used,key.id,4);
 append_text(line,&used," rp=");append_hex(line,&used,key.rp,4);
 append_text(line,&used," counter=");append_u32(line,&used,key.counter);
 append_text(line,&used,key.discoverable?" discoverable=yes\r\n":" discoverable=no\r\n");
 line[used]=0;log_puts(line);
}

static void execute_command(void){
 command[command_length]=0;
 if(!command_length)return;
 if(!strcmp(command,"help")){
  log_puts("Commands: help, status, keys list, pin status, pin set <4-63 digit PIN>\r\n");
 }else if(!strcmp(command,"pin status")){
  log_puts(pin_uv_configured()?"PIN is configured\r\n":"PIN is not configured\r\n");
 }else if(command_length>=8&&!memcmp(command,"pin set ",8)){
  if(pin_uv_set_from_console((const uint8_t*)command+8,command_length-8))
   log_puts("PIN verifier stored\r\n");
  else log_puts("ERR PIN must contain 4-63 ASCII digits\r\n");
 }else if(!strcmp(command,"status")){
  char line[128];uint32_t used=0;
  append_text(line,&used,"uptime_ms=");append_u32(line,&used,platform_millis());
  append_text(line,&used," keys=");append_u32(line,&used,credential_list_count());
  append_text(line,&used," cdc_rx_dropped=");append_u32(line,&used,usb_cdc_rx_dropped());
  append_text(line,&used," cdc_tx_dropped=");append_u32(line,&used,usb_cdc_tx_dropped());
  append_text(line,&used,"\r\n");line[used]=0;log_puts(line);
 }else if(!strcmp(command,"keys list")){
  list_index=0;list_count=credential_list_count();listing=true;
  if(!list_count){log_puts("No stored credentials\r\n");listing=false;}
  else{
   char line[48];uint32_t used=0;
   append_text(line,&used,"Stored credentials: ");append_u32(line,&used,list_count);
   append_text(line,&used," (id and RP are 4-byte fingerprints)\r\n");
   line[used]=0;log_puts(line);
  }
 }else{
  log_puts("ERR unknown command; send help\r\n");
 }
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
