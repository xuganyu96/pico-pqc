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

# Source files
include_directories(src src/common)
set(ML_KEM_512_SRC_FILES
  src/crypto_kem/ml-kem-512/clean/cbd.c 
  src/crypto_kem/ml-kem-512/clean/indcpa.c
  src/crypto_kem/ml-kem-512/clean/kem.c
  src/crypto_kem/ml-kem-512/clean/ntt.c
  src/crypto_kem/ml-kem-512/clean/poly.c
  src/crypto_kem/ml-kem-512/clean/polyvec.c
  src/crypto_kem/ml-kem-512/clean/reduce.c
  src/crypto_kem/ml-kem-512/clean/symmetric-shake.c
  src/crypto_kem/ml-kem-512/clean/verify.c
)
set(ML_KEM_768_SRC_FILES
  src/crypto_kem/ml-kem-768/clean/cbd.c 
  src/crypto_kem/ml-kem-768/clean/indcpa.c
  src/crypto_kem/ml-kem-768/clean/kem.c
  src/crypto_kem/ml-kem-768/clean/ntt.c
  src/crypto_kem/ml-kem-768/clean/poly.c
  src/crypto_kem/ml-kem-768/clean/polyvec.c
  src/crypto_kem/ml-kem-768/clean/reduce.c
  src/crypto_kem/ml-kem-768/clean/symmetric-shake.c
  src/crypto_kem/ml-kem-768/clean/verify.c
)
set(ML_KEM_1024_SRC_FILES
  src/crypto_kem/ml-kem-1024/clean/cbd.c 
  src/crypto_kem/ml-kem-1024/clean/indcpa.c
  src/crypto_kem/ml-kem-1024/clean/kem.c
  src/crypto_kem/ml-kem-1024/clean/ntt.c
  src/crypto_kem/ml-kem-1024/clean/poly.c
  src/crypto_kem/ml-kem-1024/clean/polyvec.c
  src/crypto_kem/ml-kem-1024/clean/reduce.c
  src/crypto_kem/ml-kem-1024/clean/symmetric-shake.c
  src/crypto_kem/ml-kem-1024/clean/verify.c
)
set(HQC_128_SRC_FILES
  src/crypto_kem/hqc-128/clean/code.c
  src/crypto_kem/hqc-128/clean/fft.c
  src/crypto_kem/hqc-128/clean/gf.c
  src/crypto_kem/hqc-128/clean/gf2x.c
  src/crypto_kem/hqc-128/clean/hqc.c
  src/crypto_kem/hqc-128/clean/kem.c
  src/crypto_kem/hqc-128/clean/parsing.c
  src/crypto_kem/hqc-128/clean/reed_muller.c
  src/crypto_kem/hqc-128/clean/reed_solomon.c
  src/crypto_kem/hqc-128/clean/shake_ds.c
  src/crypto_kem/hqc-128/clean/shake_prng.c
  src/crypto_kem/hqc-128/clean/vector.c
)
set(HQC_192_SRC_FILES
  src/crypto_kem/hqc-192/clean/code.c
  src/crypto_kem/hqc-192/clean/fft.c
  src/crypto_kem/hqc-192/clean/gf.c
  src/crypto_kem/hqc-192/clean/gf2x.c
  src/crypto_kem/hqc-192/clean/hqc.c
  src/crypto_kem/hqc-192/clean/kem.c
  src/crypto_kem/hqc-192/clean/parsing.c
  src/crypto_kem/hqc-192/clean/reed_muller.c
  src/crypto_kem/hqc-192/clean/reed_solomon.c
  src/crypto_kem/hqc-192/clean/shake_ds.c
  src/crypto_kem/hqc-192/clean/shake_prng.c
  src/crypto_kem/hqc-192/clean/vector.c
)
set(HQC_256_SRC_FILES
  src/crypto_kem/hqc-256/clean/code.c
  src/crypto_kem/hqc-256/clean/fft.c
  src/crypto_kem/hqc-256/clean/gf.c
  src/crypto_kem/hqc-256/clean/gf2x.c
  src/crypto_kem/hqc-256/clean/hqc.c
  src/crypto_kem/hqc-256/clean/kem.c
  src/crypto_kem/hqc-256/clean/parsing.c
  src/crypto_kem/hqc-256/clean/reed_muller.c
  src/crypto_kem/hqc-256/clean/reed_solomon.c
  src/crypto_kem/hqc-256/clean/shake_ds.c
  src/crypto_kem/hqc-256/clean/shake_prng.c
  src/crypto_kem/hqc-256/clean/vector.c
)
set(MCELIECE_348864F_SRC_FILES
  src/crypto_kem/mceliece348864f/clean/aes256ctr.c
  src/crypto_kem/mceliece348864f/clean/benes.c
  src/crypto_kem/mceliece348864f/clean/bm.c
  src/crypto_kem/mceliece348864f/clean/controlbits.c
  src/crypto_kem/mceliece348864f/clean/crypto_int16.c
  src/crypto_kem/mceliece348864f/clean/crypto_int32.c
  src/crypto_kem/mceliece348864f/clean/crypto_uint16.c
  src/crypto_kem/mceliece348864f/clean/crypto_uint32.c
  src/crypto_kem/mceliece348864f/clean/crypto_uint64.c
  src/crypto_kem/mceliece348864f/clean/decrypt.c
  src/crypto_kem/mceliece348864f/clean/encrypt.c
  src/crypto_kem/mceliece348864f/clean/gf.c
  src/crypto_kem/mceliece348864f/clean/operations.c
  src/crypto_kem/mceliece348864f/clean/pk_gen.c
  src/crypto_kem/mceliece348864f/clean/root.c
  src/crypto_kem/mceliece348864f/clean/sk_gen.c
  src/crypto_kem/mceliece348864f/clean/synd.c
  src/crypto_kem/mceliece348864f/clean/transpose.c
  src/crypto_kem/mceliece348864f/clean/util.c
)
set(PQCLEAN_SRC_FILES 
  ${ML_KEM_512_SRC_FILES}
  ${ML_KEM_768_SRC_FILES}
  ${ML_KEM_1024_SRC_FILES}
  ${HQC_128_SRC_FILES}
  ${HQC_192_SRC_FILES}
  ${HQC_256_SRC_FILES}
  ${MCELIECE_348864F_SRC_FILES}
)
set(COMMON_SRC_FILES 
  src/common/aes.c
  src/common/fips202.c
  src/common/nistseedexpander.c
  src/common/randombytes.c
  src/common/sha2.c
  src/common/sp800-185.c
)

# Binaries
add_executable(busybox src/busybox.c ${COMMON_SRC_FILES})
pico_enable_stdio_uart(busybox 0)
pico_enable_stdio_usb(busybox 1)
target_link_libraries(busybox pico_stdlib pico_rand)
pico_add_extra_outputs(busybox)

add_executable(
  pqclean_speed 
  src/pqclean_speed.c 
  ${COMMON_SRC_FILES}
  ${PQCLEAN_SRC_FILES}
)
pico_enable_stdio_uart(pqclean_speed 0)
pico_enable_stdio_usb(pqclean_speed 1)
target_link_libraries(pqclean_speed pico_stdlib pico_rand)
pico_add_extra_outputs(pqclean_speed)
