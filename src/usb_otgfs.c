#include "usb_otgfs.h"
#include "usb_descriptors.h"
#include "usb_composite.h"
#include "platform.h"
#include <string.h>
#define R(a) (*(volatile uint32_t *)(a))
#define B 0x50000000u
#define GOTGCTL R(B+0x000) 
#define GAHBCFG R(B+0x008)
#define GUSBCFG R(B+0x00c)
#define GRSTCTL R(B+0x010)
#define GINTSTS R(B+0x014)
#define GINTMSK R(B+0x018)
#define GRXSTSP R(B+0x020)
#define GRXFSIZ R(B+0x024)
#define DIEPTXF0 R(B+0x028)
#define GCCFG R(B+0x038)
#define DCFG R(B+0x800)
#define DCTL R(B+0x804)
#define DIEPMSK R(B+0x810)
#define DOEPMSK R(B+0x814)
#define DAINT R(B+0x818)
#define DAINTMSK R(B+0x81c)
#define DIEPCTL(n) R(B+0x900u+(n)*0x20u)
#define DIEPINT(n) R(B+0x908u+(n)*0x20u)
#define DIEPTSIZ(n) R(B+0x910u+(n)*0x20u)
#define DTXFSTS(n) R(B+0x918u+(n)*0x20u)
#define DOEPCTL(n) R(B+0xb00u+(n)*0x20u)
#define DOEPINT(n) R(B+0xb08u+(n)*0x20u)
#define DOEPTSIZ(n) R(B+0xb10u+(n)*0x20u)
#define FIFO(n) ((volatile uint32_t *)(B+0x1000u+(n)*0x1000u))
static uint8_t configured,address_pending,ep0buf[128];
volatile uint32_t usb_debug_irq_count,usb_debug_reset_count,usb_debug_rx_count;
volatile uint32_t usb_debug_setup_count,usb_debug_ep0_in_count,usb_debug_last_setup;
volatile uint32_t usb_debug_last_rx_status,usb_debug_oversize_count;
static uint8_t line_coding[7]={0x00,0xc2,0x01,0x00,0,0,8};
static const uint8_t lang[]={4,3,0x09,0x04};
static const uint8_t manufacturer[]={18,3,'C',0,'o',0,'d',0,'e',0,'x',0,' ',0,'L',0,'a',0};
static const uint8_t product[]={24,3,'S',0,'T',0,'M',0,'3',0,'2',0,' ',0,'F',0,'I',0,'D',0,'O',0,'2',0};
static void fifo_write(uint8_t ep,const uint8_t*d,uint16_t n){volatile uint32_t*f=FIFO(ep);for(uint16_t i=0;i<n;i+=4){uint32_t w=0;uint16_t r=(uint16_t)(n-i);if(r>4)r=4;memcpy(&w,d+i,r);*f=w;}}
int usb_otgfs_write(uint8_t ep,const uint8_t*d,uint16_t n){if(ep>3||n>64)return 0;if(DIEPCTL(ep)&(1u<<31))return 0;DIEPTSIZ(ep)=((uint32_t)1<<19)|n;DIEPCTL(ep)|=(1u<<31)|(1u<<26);fifo_write(ep,d,n);return 1;}
static void ep0_out_arm(void){DOEPTSIZ(0)=(1u<<29)|(1u<<19)|64u;DOEPCTL(0)|=(1u<<31)|(1u<<26);}
static void ep0_send(const uint8_t*d,uint16_t n,uint16_t requested){if(n>requested)n=requested;if(n>64)n=64;usb_otgfs_write(0,d,n);}
static void configure_eps(void){
 DIEPCTL(1)=64u|(3u<<18)|(1u<<22)|(1u<<15);DOEPCTL(1)=64u|(3u<<18)|(1u<<15);
 DIEPCTL(2)=16u|(3u<<18)|(2u<<22)|(1u<<15);
 DIEPCTL(3)=64u|(2u<<18)|(3u<<22)|(1u<<15);DOEPCTL(3)=64u|(2u<<18)|(1u<<15);
 DAINTMSK|=(1u<<1)|(1u<<2)|(1u<<3)|(1u<<17)|(1u<<19); configured=1;
}
static void setup(const uint8_t*s){uint8_t bm=s[0],req=s[1];uint16_t val=(uint16_t)s[2]|((uint16_t)s[3]<<8),idx=(uint16_t)s[4]|((uint16_t)s[5]<<8),len=(uint16_t)s[6]|((uint16_t)s[7]<<8);(void)idx;usb_debug_setup_count++;usb_debug_last_setup=(uint32_t)bm|((uint32_t)req<<8)|((uint32_t)val<<16);
 if((bm&0x60u)==0){if(req==6){const uint8_t*d=0;uint16_t n=0;uint8_t type=(uint8_t)(val>>8),di=(uint8_t)val;if(type==1){d=usb_device_descriptor;n=18;}else if(type==2){d=usb_configuration_descriptor;n=usb_configuration_descriptor_length;}else if(type==3){if(di==0){d=lang;n=sizeof lang;}else if(di==1){d=manufacturer;n=sizeof manufacturer;}else{d=product;n=sizeof product;}}else if(type==0x22){d=usb_fido_report_descriptor;n=34;}if(d)ep0_send(d,n,len);else DIEPCTL(0)|=1u<<21;}else if(req==5){address_pending=(uint8_t)val;ep0_send(ep0buf,0,0);}else if(req==9){configure_eps();ep0_send(ep0buf,0,0);}else if(req==8){ep0buf[0]=configured;ep0_send(ep0buf,1,len);}else ep0_send(ep0buf,0,0);
 }else if((bm&0x60u)==0x20u){if(req==0x21){ep0_send(line_coding,7,len);}else if(req==0x20){ep0_send(ep0buf,0,0);}else ep0_send(ep0buf,0,0);}
 ep0_out_arm();
}
static void reset(void){usb_debug_reset_count++;configured=0;DCFG&=~(0x7fu<<4);DIEPCTL(0)=0;DOEPCTL(0)=0;DAINTMSK=0x00010001u;DIEPMSK=1u;DOEPMSK=(1u<<3)|1u;ep0_out_arm();}
void usb_otgfs_init(void){platform_usb_pins_init();GAHBCFG=0;GUSBCFG|=(1u<<30)|(1u<<6);for(volatile uint32_t i=0;i<5000000;i++){}while(!(GRSTCTL&(1u<<31))){}GRSTCTL|=1u;while(GRSTCTL&1u){}GCCFG|=(1u<<16)|(1u<<21);GRXFSIZ=128;DIEPTXF0=(64u<<16)|128u;R(B+0x104)=(64u<<16)|192u;R(B+0x108)=(32u<<16)|256u;R(B+0x10c)=(64u<<16)|288u;DCFG=3u;GINTSTS=0xffffffffu;GINTMSK=(1u<<12)|(1u<<13)|(1u<<4)|(1u<<18)|(1u<<19);GAHBCFG=1u;DCTL&=~(1u<<1);R(0xe000e108u)=1u<<3;}
uint8_t usb_otgfs_configured(void){return configured;}
void usb_otgfs_irq(void){usb_debug_irq_count++;uint32_t st=GINTSTS&GINTMSK;if(st&(1u<<12)){GINTSTS=1u<<12;reset();}if(st&(1u<<4)){usb_debug_rx_count++;uint32_t x=GRXSTSP;usb_debug_last_rx_status=x;uint8_t ep=(uint8_t)(x&15u),pkt=(uint8_t)((x>>17)&15u);uint16_t n=(uint16_t)((x>>4)&0x7ffu);uint8_t b[64]={0};volatile uint32_t*f=FIFO(0);uint16_t copied=0;for(uint16_t i=0;i<n;i+=4){uint32_t w=*f;if(i<sizeof b){uint16_t r=(uint16_t)(n-i);if(r>4)r=4;if((uint16_t)(i+r)>sizeof b)r=(uint16_t)(sizeof b-i);memcpy(b+i,&w,r);copied=(uint16_t)(i+r);}}if(n>sizeof b)usb_debug_oversize_count++;if(pkt==6u&&copied==8u)setup(b);else if(pkt==2u&&ep==1u&&n==64u)usb_fido_hid_rx(b,n);ep0_out_arm();}if(st&(1u<<18)){uint32_t a=DAINT;for(uint8_t ep=0;ep<4;ep++)if(a&(1u<<ep)){uint32_t q=DIEPINT(ep);DIEPINT(ep)=q;if(ep==0){usb_debug_ep0_in_count++;if(address_pending){DCFG=(DCFG&~(0x7fu<<4))|((uint32_t)address_pending<<4);address_pending=0;}}}}if(st&(1u<<13))GINTSTS=1u<<13;}
