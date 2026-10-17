.syntax unified
.thumb
.cpu cortex-m4
.section .isr_vector,"a",%progbits
.global g_pfnVectors
g_pfnVectors:
  .word 0x20020000
  .word Reset_Handler
  .rept 13
  .word Default_Handler
  .endr
  .word SysTick_Handler
  .rept 67
  .word Default_Handler
  .endr
  .word OTG_FS_IRQHandler
  .rept 14
  .word Default_Handler
  .endr
.text
.global Reset_Handler
.type Reset_Handler,%function
Reset_Handler:
  ldr r0, =_sdata
  ldr r1, =_edata
  ldr r2, =_etext
1: cmp r0, r1
   bcs 2f
   ldr r3, [r2], #4
   str r3, [r0], #4
   b 1b
2: ldr r0, =_sbss
   ldr r1, =_ebss
   movs r2, #0
3: cmp r0, r1
   bcs 4f
   str r2, [r0], #4
   b 3b
4: bl SystemInit
   bl main
5: b 5b
.size Reset_Handler, .-Reset_Handler
.global Default_Handler
.type Default_Handler,%function
Default_Handler: b .
.size Default_Handler, .-Default_Handler
