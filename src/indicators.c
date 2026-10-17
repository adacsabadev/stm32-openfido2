#include "indicators.h"
#include "platform.h"
#include "stm32f4xx_hal.h"
#include "log.h"
static bool activity, result_active, result_ok, waiting, accepted;
static bool raw_button, stable_button, release_seen;
static uint32_t activity_start, result_start, button_change, presence_start;
static void led(uint16_t pin, bool on) {
 HAL_GPIO_WritePin(GPIOD, pin, on ? GPIO_PIN_SET : GPIO_PIN_RESET);
}
void indicators_init(void) {
 __HAL_RCC_GPIOA_CLK_ENABLE();
 GPIO_InitTypeDef gpio = {0};
 gpio.Pin=GPIO_PIN_0; gpio.Mode=GPIO_MODE_INPUT; gpio.Pull=GPIO_NOPULL;
 HAL_GPIO_Init(GPIOA,&gpio);
 raw_button=stable_button=HAL_GPIO_ReadPin(GPIOA,GPIO_PIN_0)==GPIO_PIN_SET;
 button_change=platform_millis();
 HAL_GPIO_WritePin(GPIOD,GPIO_PIN_12|GPIO_PIN_13|GPIO_PIN_14|GPIO_PIN_15,GPIO_PIN_RESET);
}
void indicators_activity(void) {
 activity=true; activity_start=platform_millis(); led(GPIO_PIN_15,true);
}
void indicators_result(bool success) {
 result_active=true; result_ok=success; result_start=platform_millis();
 led(GPIO_PIN_12,success); led(GPIO_PIN_14,!success);
}
void presence_begin(void) {
 waiting=true; accepted=false; release_seen=false;
 presence_start=button_change=platform_millis();
 raw_button=stable_button=HAL_GPIO_ReadPin(GPIOA,GPIO_PIN_0)==GPIO_PIN_SET;
 led(GPIO_PIN_13,true);
 log_puts("Presence required: release then press blue USER B1 (PA0)\r\n");
}
void presence_cancel(void) {
 waiting=false; accepted=false; release_seen=false; led(GPIO_PIN_13,false);
}
bool presence_take(void) {
 bool ready=accepted; accepted=false; return ready;
}
void indicators_poll(void) {
 uint32_t now=platform_millis();
 bool sample=HAL_GPIO_ReadPin(GPIOA,GPIO_PIN_0)==GPIO_PIN_SET;
 if(sample!=raw_button){raw_button=sample;button_change=now;}
 if((uint32_t)(now-button_change)>=30u){
  if(waiting&&!raw_button)release_seen=true;
  if(raw_button!=stable_button){
   stable_button=raw_button;
   if(waiting&&stable_button&&release_seen){
    accepted=true; waiting=false; led(GPIO_PIN_13,false);
    log_puts("Presence confirmed: fresh USER button press\r\n");
   }
  }
 }
 if(waiting){
  led(GPIO_PIN_13,((uint32_t)(now-presence_start)/250u)%2u==0);
  if((uint32_t)(now-presence_start)>=30000u){
   presence_cancel();indicators_result(false);log_puts("Presence timed out\r\n");
  }
 }
 if(activity&&(uint32_t)(now-activity_start)>=100u){activity=false;led(GPIO_PIN_15,false);}
 if(result_active&&(uint32_t)(now-result_start)>=1000u){
  result_active=false;led(GPIO_PIN_12,false);led(GPIO_PIN_14,false);
 }
 (void)result_ok;
}
