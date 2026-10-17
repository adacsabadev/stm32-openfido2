cmake_minimum_required(VERSION 3.22)
project(stm32-openfido2 C ASM)

set(CMAKE_SYSTEM_NAME Generic)
set(CMAKE_TRY_COMPILE_TARGET_TYPE STATIC_LIBRARY)
set(MCU_FLAGS -mcpu=cortex-m4 -mthumb -mfpu=fpv4-sp-d16 -mfloat-abi=hard)
add_compile_options(${MCU_FLAGS} -ffreestanding -fno-builtin -ffunction-sections -fdata-sections -Wall -Wextra -Werror -Wno-unused-parameter -Wno-pointer-sign -Wno-sign-compare -Wno-attributes -g3 -O0)
add_link_options(${MCU_FLAGS} -T${CMAKE_SOURCE_DIR}/linker/stm32f407vg.ld -nostartfiles -Wl,--gc-sections -Wl,-Map=${CMAKE_BINARY_DIR}/stm32-openfido2.map)

add_executable(stm32-openfido2
  startup/startup_stm32f407.s
  src/main.c
  src/indicators.c
  src/platform.c
  src/log.c
  src/debug_console.c
  src/fido2.c
  src/ctaphid.c
  src/ctap2.c
  src/pin_uv.c
  src/cbor_min.c
  src/credential.c
  vendor/mbedtls/library/bignum.c
  vendor/mbedtls/library/bignum_core.c
  vendor/mbedtls/library/bignum_mod.c
  vendor/mbedtls/library/bignum_mod_raw.c
  vendor/mbedtls/library/constant_time.c
  vendor/mbedtls/library/ecp.c
  vendor/mbedtls/library/ecp_curves.c
  vendor/mbedtls/library/ecdsa.c
  vendor/mbedtls/library/asn1write.c
  vendor/mbedtls/library/asn1parse.c
  vendor/mbedtls/library/sha256.c
  vendor/mbedtls/library/aes.c
  vendor/mbedtls/library/platform_util.c
  vendor/st/hal/src/stm32f4xx_hal_flash.c
  src/usb_descriptors.c
  src/usb_composite.c
  src/usb_device_st.c
  src/usbd_conf.c
  src/usbd_desc.c
  src/usbd_u2f_hid_if.c
  src/usbd_composite_st.c
  src/system_stm32f4xx.c
  src/syscalls.c
  vendor/st/usb/Core/Src/usbd_core.c
  vendor/st/usb/Core/Src/usbd_ctlreq.c
  vendor/st/usb/Core/Src/usbd_ioreq.c
  vendor/st/hal/src/stm32f4xx_hal.c
  vendor/st/hal/src/stm32f4xx_hal_cortex.c
  vendor/st/hal/src/stm32f4xx_hal_gpio.c
  vendor/st/hal/src/stm32f4xx_hal_pcd.c
  vendor/st/hal/src/stm32f4xx_hal_pcd_ex.c
  vendor/st/hal/src/stm32f4xx_hal_rcc.c
  vendor/st/hal/src/stm32f4xx_hal_rcc_ex.c
  vendor/st/hal/src/stm32f4xx_hal_pwr.c
  vendor/st/hal/src/stm32f4xx_hal_pwr_ex.c
  vendor/st/hal/src/stm32f4xx_ll_usb.c
)
target_include_directories(stm32-openfido2 PRIVATE include vendor/mbedtls/include vendor/st/usb/Core/Inc vendor/st/hal/inc vendor/st/cmsis/include vendor/st/cmsis/device)
target_compile_definitions(stm32-openfido2 PRIVATE STM32F407xx USE_HAL_DRIVER)
target_compile_definitions(stm32-openfido2 PRIVATE MBEDTLS_CONFIG_FILE="crypto_config.h")
target_link_libraries(stm32-openfido2 c gcc)
set_source_files_properties(
 vendor/mbedtls/library/bignum.c
 vendor/mbedtls/library/bignum_core.c
 vendor/mbedtls/library/bignum_mod.c
 vendor/mbedtls/library/bignum_mod_raw.c
 vendor/mbedtls/library/constant_time.c
 vendor/mbedtls/library/ecp.c
 vendor/mbedtls/library/ecp_curves.c vendor/mbedtls/library/ecdsa.c
 vendor/mbedtls/library/sha256.c PROPERTIES COMPILE_OPTIONS "-O2")
add_custom_command(TARGET stm32-openfido2 POST_BUILD
  COMMAND ${CMAKE_OBJCOPY} -O binary $<TARGET_FILE:stm32-openfido2> ${CMAKE_BINARY_DIR}/stm32-openfido2.bin
  COMMAND ${CMAKE_OBJCOPY} -O ihex $<TARGET_FILE:stm32-openfido2> ${CMAKE_BINARY_DIR}/stm32-openfido2.hex)
