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
include_directories(${PICO_SDK_PATH}/src/rp2_common/hardware_base/include)
include_directories(${PICO_SDK_PATH}/src/rp2350/hardware_regs/include)
include_directories(${PICO_SDK_PATH}/src/rp2350/hardware_structs/include)

# Include liboqs, which is built externally.
if(NOT DEFINED ENV{LIBOQS_PATH})
  message(FATAL_ERROR "Must specify path to liboqs w/ LIBOQS_PATH")
endif()
set(LIBOQS_PATH $ENV{LIBOQS_PATH})
include_directories(${LIBOQS_PATH}/include)
link_directories(${LIBOQS_PATH}/lib)

# IND-1CCA KEM
# TODO: build static library libind1ccakem.a
# Probably need to compile ind1cca/mlkem three times, each with MLKEM_K set to 2, 3, 4
# Don't need three separate libraries because src/ind1cca/mlkem is appropriately namespaced
set(MLKEM_SRC_FILES 
  src/ind1cca/mlkem/cbd.c
  src/ind1cca/mlkem/fips202.c
  src/ind1cca/mlkem/indcpa.c
  src/ind1cca/mlkem/keccakf1600.c
  src/ind1cca/mlkem/kem.c
  src/ind1cca/mlkem/matacc.c
  src/ind1cca/mlkem/ntt.c
  src/ind1cca/mlkem/poly.c
  src/ind1cca/mlkem/polyvec.c
  src/ind1cca/mlkem/reduce.c
  src/ind1cca/mlkem/symmetric-shake.c
  src/ind1cca/mlkem/verify.c
)
add_library(mlkem_512 OBJECT ${MLKEM_SRC_FILES})
target_compile_definitions(mlkem_512 PRIVATE MLKEM_K=2)
target_include_directories(mlkem_512 PRIVATE src/ind1cca/mlkem)
add_library(mlkem_768 OBJECT ${MLKEM_SRC_FILES})
target_compile_definitions(mlkem_768 PRIVATE MLKEM_K=3)
target_include_directories(mlkem_768 PRIVATE src/ind1cca/mlkem)
add_library(mlkem_1024 OBJECT ${MLKEM_SRC_FILES})
target_compile_definitions(mlkem_1024 PRIVATE MLKEM_K=4)
target_include_directories(mlkem_1024 PRIVATE src/ind1cca/mlkem)
add_library(ind1cca STATIC
    $<TARGET_OBJECTS:mlkem_512>
    $<TARGET_OBJECTS:mlkem_768>
    $<TARGET_OBJECTS:mlkem_1024>
)
set_target_properties(ind1cca PROPERTIES OUTPUT_NAME "ind1cca")

# Source files
set(SRC_FILES
  src/randombytes.c)

# Binaries
add_executable(pico-oqs src/pico-oqs.c ${SRC_FILES})
pico_enable_stdio_uart(pico-oqs 0)
pico_enable_stdio_usb(pico-oqs 1)
target_link_libraries(pico-oqs pico_stdlib ${LIBOQS_PATH}/lib/liboqs.a)
pico_add_extra_outputs(pico-oqs)

add_executable(pico-rng src/pico-rng.c ${SRC_FILES})
pico_enable_stdio_uart(pico-rng 0)
pico_enable_stdio_usb(pico-rng 1)
# TODO: needed to manually add pico_rand :(
target_link_libraries(pico-rng pico_stdlib pico_rand ${LIBOQS_PATH}/lib/liboqs.a)
pico_add_extra_outputs(pico-rng)

add_executable(speed src/speed.c ${SRC_FILES})
pico_enable_stdio_uart(speed 0)
pico_enable_stdio_usb(speed 1)
target_link_libraries(speed pico_stdlib)
pico_add_extra_outputs(speed)

add_executable(oqs_speed src/oqs_speed.c ${SRC_FILES})
pico_enable_stdio_uart(oqs_speed 0)
pico_enable_stdio_usb(oqs_speed 1)
target_link_libraries(oqs_speed pico_stdlib pico_rand ind1cca ${LIBOQS_PATH}/lib/liboqs.a)
pico_add_extra_outputs(oqs_speed)
