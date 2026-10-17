#include "usb_composite.h"
#include "ctaphid.h"
#include "usb_device.h"
#include "usbd_u2fhid.h"
#include "stm32f4xx_hal.h"
#include <string.h>
#include "indicators.h"
extern USBD_HandleTypeDef hUsbDeviceFS;
extern PCD_HandleTypeDef hpcd_USB_OTG_FS;
extern uint8_t composite_cdc_send(USBD_HandleTypeDef*,uint8_t*,uint16_t);
#define CDC_CAP 8192u
#define CDC_RX_CAP 256u
#define HID_CAP 32u
static uint8_t cdc[CDC_CAP],cdc_packet[64],cdc_rx[CDC_RX_CAP],hid_tx[HID_CAP][64],hid_packet[64],hid_rx[8][64];
static volatile unsigned ch,ct,th,tt,rh,rt,crh,crt;
static volatile uint32_t cdc_dropped,cdc_rx_overflow;
volatile uint32_t hid_dropped;
static uint32_t lock(void){uint32_t p=__get_PRIMASK();__disable_irq();return p;}
static void unlock(uint32_t p){__set_PRIMASK(p);}
void usb_composite_init(void){ch=ct=th=tt=rh=rt=crh=crt=0;MX_USB_DEVICE_Init();}
void usb_composite_poll(void){
 if(rt!=rh){uint8_t packet[64];uint32_t p=lock();memcpy(packet,hid_rx[rt],64);rt=(rt+1)%8;unlock(p);indicators_activity();ctaphid_receive(packet);}
 usb_composite_tx_poll();
}
void usb_composite_tx_poll(void){
 uint32_t p=lock();
 if(tt!=th){memcpy(hid_packet,hid_tx[tt],64);if(USBD_U2F_HID_SendReport(&hUsbDeviceFS,hid_packet,64)==USBD_OK)tt=(tt+1)%HID_CAP;}
 if(ct!=ch){unsigned n=0,i=ct;while(n<63&&i!=ch){cdc_packet[n++]=cdc[i];i=(i+1)%CDC_CAP;}
  if(composite_cdc_send(&hUsbDeviceFS,cdc_packet,(uint16_t)n)==USBD_OK)ct=i;
 }
 unlock(p);
}
void usb_fido_hid_write(const uint8_t*d,uint32_t n){if(n!=64)return;uint32_t p=lock();unsigned next=(th+1)%HID_CAP;if(next==tt)hid_dropped++;else{memcpy(hid_tx[th],d,64);th=next;}unlock(p);}
void usb_fido_hid_rx(const uint8_t*d,uint32_t n){if(n!=64)return;unsigned next=(rh+1)%8;if(next==rt)hid_dropped++;else{memcpy(hid_rx[rh],d,64);rh=next;}}
void usb_cdc_write(const uint8_t*d,uint32_t n){uint32_t p=lock();while(n--){uint8_t byte=*d++;unsigned next=(ch+1)%CDC_CAP;if(next==ct){cdc_dropped++;continue;}cdc[ch]=byte;ch=next;}unlock(p);}
void usb_cdc_rx(const uint8_t*d,uint32_t n){while(n--){unsigned next=(crh+1)%CDC_RX_CAP;if(next==crt){cdc_rx_overflow++;d++;continue;}cdc_rx[crh]=*d++;crh=next;}}
bool usb_cdc_read(uint8_t*byte){uint32_t p=lock();if(crt==crh){unlock(p);return false;}*byte=cdc_rx[crt];crt=(crt+1)%CDC_RX_CAP;unlock(p);return true;}
uint32_t usb_cdc_pending(void){return(ch+CDC_CAP-ct)%CDC_CAP;}
uint32_t usb_cdc_rx_dropped(void){return cdc_rx_overflow;}
uint32_t usb_cdc_tx_dropped(void){return cdc_dropped;}
void OTG_FS_IRQHandler(void){HAL_PCD_IRQHandler(&hpcd_USB_OTG_FS);}
