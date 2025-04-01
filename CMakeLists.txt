# Generated Cmake Pico project file

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

project(pico-oqs C CXX ASM)

pico_sdk_init()

# Set toolchain and SDK includes
set(ARM_GCC_PATH "/opt/homebrew/Cellar/arm-none-eabi-gcc@8/8.5.0_2")
include_directories(${ARM_GCC_PATH}/lib/arm-none-eabi-gcc/8/gcc/arm-none-eabi/8.5.0/include)
include_directories(${ARM_GCC_PATH}/lib/arm-none-eabi-gcc/8/gcc/arm-none-eabi/8.5.0/include-fixed)
include_directories(${ARM_GCC_PATH}/arm-none-eabi/include)
include_directories(${CMAKE_CURRENT_LIST_DIR})
include_directories(${PICO_SDK_PATH}/src/rp2_common/pico_cyw43_arch/include) # Wifi header
include_directories(${PICO_SDK_PATH}/src/rp2_common/pico_rand/include) # RNG header

# Include liboqs
if(NOT DEFINED ENV{LIBOQS_PATH})
  message(FATAL_ERROR "Must specify path to liboqs w/ LIBOQS_PATH")
endif()
set(LIBOQS_PATH $ENV{LIBOQS_PATH})
include_directories(${LIBOQS_PATH}/include)
link_directories(${LIBOQS_PATH}/lib)


add_executable(pico-oqs src/pico-oqs.c)
pico_set_program_name(pico-oqs "pico-oqs")
pico_set_program_version(pico-oqs "0.1")
pico_enable_stdio_uart(pico-oqs 0)
pico_enable_stdio_usb(pico-oqs 1)
target_link_libraries(pico-oqs pico_stdlib ${LIBOQS_PATH}/lib/liboqs.a)
pico_add_extra_outputs(pico-oqs)

add_executable(pico-rng src/pico-rng.c)
pico_set_program_name(pico-rng "pico-rng")
pico_set_program_version(pico-rng "0.1")
pico_enable_stdio_uart(pico-rng 0)
pico_enable_stdio_usb(pico-rng 1)
# TODO: needed to manually add pico_rand :(
target_link_libraries(pico-rng pico_stdlib pico_rand ${LIBOQS_PATH}/lib/liboqs.a)
pico_add_extra_outputs(pico-rng)

