#include "platform.h"
#include <stdint.h>
#include "stm32f4xx_hal.h"
#define REG32(a) (*(volatile uint32_t *)(a))
#define RCC_CR REG32(0x40023800u)
#define RCC_PLLCFGR REG32(0x40023804u)
#define RCC_CFGR REG32(0x40023808u)
#define RCC_AHB1ENR REG32(0x40023830u)
#define RCC_AHB2ENR REG32(0x40023834u)
#define PWR_CR REG32(0x40007000u)
#define FLASH_ACR REG32(0x40023c00u)
#define GPIOA_MODER REG32(0x40020000u)
#define GPIOA_OSPEEDR REG32(0x40020008u)
#define GPIOA_AFRH REG32(0x40020024u)
#define GPIOD_MODER REG32(0x40020c00u)
#define GPIOD_BSRR REG32(0x40020c18u)
#define SYST_CSR REG32(0xe000e010u)
#define SYST_RVR REG32(0xe000e014u)
#define SYST_CVR REG32(0xe000e018u)
static volatile uint32_t ticks;
void SysTick_Handler(void){++ticks;HAL_IncTick();}
static void clock_72mhz_usb48(void){
 RCC_AHB1ENR|=1u<<28; PWR_CR|=3u<<14;
 RCC_CR|=1u<<16; while(!(RCC_CR&(1u<<17))){}
 RCC_PLLCFGR=8u|(288u<<6)|(1u<<16)|(1u<<22)|(6u<<24);
 FLASH_ACR=(1u<<8)|(1u<<9)|(1u<<10)|2u;
 RCC_CFGR=(5u<<10); RCC_CR|=1u<<24; while(!(RCC_CR&(1u<<25))){}
 RCC_CFGR=(RCC_CFGR&~3u)|2u; while(((RCC_CFGR>>2)&3u)!=2u){}
}
void platform_init(void){clock_72mhz_usb48();SystemCoreClock=72000000u;RCC_AHB1ENR|=1u<<3;GPIOD_MODER=(GPIOD_MODER&~(0xffu<<24))|(0x55u<<24);SYST_RVR=72000u-1u;SYST_CVR=0;SYST_CSR=7;}
void platform_usb_pins_init(void){RCC_AHB1ENR|=1u;GPIOA_MODER=(GPIOA_MODER&~((3u<<22)|(3u<<24)))|(2u<<22)|(2u<<24);GPIOA_OSPEEDR|=(3u<<22)|(3u<<24);GPIOA_AFRH=(GPIOA_AFRH&~((0xfu<<12)|(0xfu<<16)))|(10u<<12)|(10u<<16);RCC_AHB2ENR|=1u<<7;}
uint32_t platform_millis(void){return ticks;}
void platform_idle(void){__asm volatile("wfi");}
void platform_led(uint32_t pin){GPIOD_BSRR=(0xf000u<<16)|(1u<<pin);}
