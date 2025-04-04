cmake_minimum_required(VERSION 3.13)

set(CMAKE_C_STANDARD 11)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# Initialise pico_sdk from installed location
# (note this can come from environment, CMake cache etc)

# == DO NOT EDIT THE FOLLOWING LINES for the Raspberry Pi Pico VS Code Extension to work ==
if(WIN32)
    set(USERHOME $ENV{USERPROFILE})
else()
    set(USERHOME $ENV{HOME})
endif()
set(sdkVersion 2.1.1)
set(toolchainVersion 14_2_Rel1)
set(picotoolVersion 2.1.1)
set(picoVscode ${USERHOME}/.pico-sdk/cmake/pico-vscode.cmake)
if (EXISTS ${picoVscode})
    include(${picoVscode})
endif()
# ====================================================================================
set(PICO_BOARD pico2_w CACHE STRING "Board type")

# Pull in Raspberry Pi Pico SDK (must be before project)
include(pico_sdk_import.cmake)

project(pico-pqc C CXX ASM)

pico_sdk_init()

# Set toolchain and SDK includes
set(ARM_GCC_PATH "/opt/homebrew/Cellar/arm-none-eabi-gcc@8/8.5.0_2")
include_directories(${ARM_GCC_PATH}/lib/arm-none-eabi-gcc/8/gcc/arm-none-eabi/8.5.0/include)
include_directories(${ARM_GCC_PATH}/lib/arm-none-eabi-gcc/8/gcc/arm-none-eabi/8.5.0/include-fixed)
include_directories(${ARM_GCC_PATH}/arm-none-eabi/include)
include_directories(${CMAKE_CURRENT_LIST_DIR})
include_directories(${PICO_SDK_PATH}/src/rp2_common/pico_cyw43_arch/include) # Wifi header
include_directories(${PICO_SDK_PATH}/src/rp2_common/pico_rand/include) # RNG header
include_directories(${PICO_SDK_PATH}/src/rp2_common/hardware_base/include)
include_directories(${PICO_SDK_PATH}/src/rp2350/hardware_regs/include)
include_directories(${PICO_SDK_PATH}/src/rp2350/hardware_structs/include)

# Source files
include_directories(src src/common)
file(GLOB CRYPTO_KEM_CLEAN_SRC src/crypto_kem/*/clean/*.c)
file(GLOB CRYPTO_SIGN_CLEAN_SRC src/crypto_sign/*/clean/*.c)
set(PQCLEAN_SRC ${CRYPTO_KEM_CLEAN_SRC} ${CRYPTO_SIGN_CLEAN_SRC})
file(GLOB COMMON_SRC src/common/*.c)

# Binaries
add_executable(busybox src/busybox.c ${COMMON_SRC})
pico_enable_stdio_uart(busybox 0)
pico_enable_stdio_usb(busybox 1)
target_link_libraries(busybox pico_stdlib pico_rand)
pico_add_extra_outputs(busybox)

add_executable(
  pqclean_speed 
  src/pqclean_speed.c 
  ${COMMON_SRC}
  ${PQCLEAN_SRC}
)
pico_enable_stdio_uart(pqclean_speed 0)
pico_enable_stdio_usb(pqclean_speed 1)
target_link_libraries(pqclean_speed pico_stdlib pico_rand)
pico_add_extra_outputs(pqclean_speed)
