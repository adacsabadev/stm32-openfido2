#include "platform.h"
#include "log.h"
#include "fido2.h"
#include "usb_composite.h"
#include "stm32f4xx_hal.h"
#include "indicators.h"
#include "debug_console.h"
#include "credential.h"

void Error_Handler(void);

int main(void)
{
    HAL_Init();
    platform_init();
    indicators_init();
    log_init();
    usb_composite_init();
    if(!credential_storage_init()){
        log_puts("FATAL credential journal recovery failed\r\n");
        for(;;){
            usb_composite_poll();
            platform_idle();
        }
    }
    fido2_init();
    log_puts("stm32-fido2 boot\r\n");
    for (;;) {
        indicators_poll();
        usb_composite_poll();
        debug_console_poll();
        fido2_poll();
        platform_idle();
    }
}
void Error_Handler(void){for(;;){}}
