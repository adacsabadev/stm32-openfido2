#include "usbd_u2f_hid_if.h"
#include "ctaphid.h"
#include "usb_descriptors.h"
static int8_t hid_init(void){return 0;}
static int8_t hid_deinit(void){return 0;}
static int8_t hid_out(uint8_t *data,uint16_t len){if(len==CTAPHID_REPORT_SIZE)ctaphid_receive(data);return 0;}
USBD_U2F_HID_ItfTypeDef USBD_U2FHID_fops_FS={(uint8_t *)usb_fido_report_descriptor,hid_init,hid_deinit,hid_out};
