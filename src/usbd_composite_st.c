/* Composite FIDO HID + CDC ACM class using ST's USB Device control core. */
#include "usbd_u2fhid.h"
#include "usb_descriptors.h"
#include "usb_composite.h"
#include "log.h"
#include <string.h>
static uint8_t hid_rx[64], cdc_rx[64], line[7]={0,0xc2,1,0,0,0,8};
static uint8_t pending_line, idle, alternate;
static volatile uint8_t hid_busy, cdc_busy, cdc_open;
static uint8_t hid_transfer[64], cdc_transfer[64];
static uint8_t init(USBD_HandleTypeDef *p,uint8_t cfg){
 (void)cfg; hid_busy=cdc_busy=cdc_open=pending_line=0;
 USBD_LL_OpenEP(p,0x81,USBD_EP_TYPE_INTR,64);
 USBD_LL_OpenEP(p,0x01,USBD_EP_TYPE_INTR,64);
 USBD_LL_OpenEP(p,0x82,USBD_EP_TYPE_INTR,16);
 USBD_LL_OpenEP(p,0x83,USBD_EP_TYPE_BULK,64);
 USBD_LL_OpenEP(p,0x03,USBD_EP_TYPE_BULK,64);
 p->pClassData=hid_rx;
 USBD_LL_PrepareReceive(p,1,hid_rx,64);
 USBD_LL_PrepareReceive(p,3,cdc_rx,64);
 log_puts("USB composite configured: FIDO HID + CDC ACM\r\n");
 return USBD_OK;
}
static uint8_t deinit(USBD_HandleTypeDef*p,uint8_t cfg){
 (void)cfg; const uint8_t eps[]={0x81,1,0x82,0x83,3};
 for(unsigned i=0;i<sizeof eps;i++)USBD_LL_CloseEP(p,eps[i]);
 p->pClassData=0;hid_busy=cdc_busy=cdc_open=0;return USBD_OK;
}
static uint8_t setup(USBD_HandleTypeDef*p,USBD_SetupReqTypedef*r){
 if((r->bmRequest&USB_REQ_TYPE_MASK)==USB_REQ_TYPE_CLASS){
  if(r->wIndex==1){
   switch(r->bRequest){
    case 0x20: if(r->wLength!=7 || (r->bmRequest&0x80))break;
     pending_line=1;return USBD_CtlPrepareRx(p,line,7);
    case 0x21: if(r->wLength!=7 || !(r->bmRequest&0x80))break;
     return USBD_CtlSendData(p,line,7);
    case 0x22: if(r->wLength)break;
     cdc_open=(r->wValue&1)!=0;
     if(cdc_open)log_puts("CDC attached: CTAP2 ES256 registration/assertion; blue USER approves orange prompt\r\n");
     return USBD_OK;
    case 0x23: if(!r->wLength)return USBD_OK;break;
   }
  }else if(r->wIndex==0){
   if(r->bRequest==0x0a){idle=(uint8_t)(r->wValue>>8);return USBD_OK;}
   if(r->bRequest==0x02)return USBD_CtlSendData(p,&idle,1);
  }
 }else if((r->bmRequest&USB_REQ_TYPE_MASK)==USB_REQ_TYPE_STANDARD){
  if(r->bRequest==USB_REQ_GET_DESCRIPTOR && r->wIndex==0){
   if((r->wValue>>8)==0x22)return USBD_CtlSendData(p,(uint8_t*)usb_fido_report_descriptor,MIN(34,r->wLength));
   if((r->wValue>>8)==0x21)return USBD_CtlSendData(p,(uint8_t*)usb_configuration_descriptor+18,MIN(9,r->wLength));
  }
  if(r->bRequest==USB_REQ_GET_INTERFACE)return USBD_CtlSendData(p,&alternate,1);
  if(r->bRequest==USB_REQ_SET_INTERFACE && r->wValue==0)return USBD_OK;
 }
 USBD_CtlError(p,r);return USBD_FAIL;
}
static uint8_t ep0_ready(USBD_HandleTypeDef*p){(void)p;if(pending_line){pending_line=0;log_puts("CDC line coding updated\r\n");}return USBD_OK;}
static uint8_t in(USBD_HandleTypeDef*p,uint8_t ep){(void)p;if(ep==1)hid_busy=0;if(ep==3)cdc_busy=0;return USBD_OK;}
static uint8_t out(USBD_HandleTypeDef*p,uint8_t ep){
 if(ep==1){usb_fido_hid_rx(hid_rx,USBD_LL_GetRxDataSize(p,1));USBD_LL_PrepareReceive(p,1,hid_rx,64);}
 if(ep==3){usb_cdc_rx(cdc_rx,USBD_LL_GetRxDataSize(p,3));USBD_LL_PrepareReceive(p,3,cdc_rx,64);}
 return USBD_OK;
}
static uint8_t* config(uint16_t*n){*n=usb_configuration_descriptor_length;return(uint8_t*)usb_configuration_descriptor;}
static uint8_t* qualifier(uint16_t*n){static uint8_t d[]={10,6,0,2,0xef,2,1,64,1,0};*n=10;return d;}
USBD_ClassTypeDef USBD_U2F_HID={init,deinit,setup,0,ep0_ready,in,out,0,0,0,config,config,config,qualifier};
uint8_t USBD_U2F_HID_RegisterInterface(USBD_HandleTypeDef*p,USBD_U2F_HID_ItfTypeDef*f){p->pUserData=f;return USBD_OK;}
uint8_t USBD_U2F_HID_SendReport(USBD_HandleTypeDef*p,uint8_t*d,uint16_t n){
 if(p->dev_state!=USBD_STATE_CONFIGURED||hid_busy)return USBD_BUSY;
 if(n>sizeof hid_transfer)return USBD_FAIL;
 memcpy(hid_transfer,d,n);hid_busy=1;return USBD_LL_Transmit(p,0x81,hid_transfer,n);
}
uint8_t composite_cdc_send(USBD_HandleTypeDef*p,uint8_t*d,uint16_t n){
 if(p->dev_state!=USBD_STATE_CONFIGURED||!cdc_open||cdc_busy)return USBD_BUSY;
 if(n>sizeof cdc_transfer)return USBD_FAIL;
 memcpy(cdc_transfer,d,n);cdc_busy=1;return USBD_LL_Transmit(p,0x83,cdc_transfer,n);
}
