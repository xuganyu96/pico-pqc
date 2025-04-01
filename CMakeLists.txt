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

# Initialise the Raspberry Pi Pico SDK
pico_sdk_init()

include_directories(/opt/homebrew/Cellar/arm-none-eabi-gcc@8/8.5.0_2/lib/arm-none-eabi-gcc/8/gcc/arm-none-eabi/8.5.0/include)
include_directories(/opt/homebrew/Cellar/arm-none-eabi-gcc@8/8.5.0_2/lib/arm-none-eabi-gcc/8/gcc/arm-none-eabi/8.5.0/include-fixed)
include_directories(/opt/homebrew/Cellar/arm-none-eabi-gcc@8/8.5.0_2/arm-none-eabi/include)
include_directories(${CMAKE_CURRENT_LIST_DIR})

# Add executable. Default name is the project name, version 0.1

add_executable(pico-oqs src/pico-oqs.c)

pico_set_program_name(pico-oqs "pico-oqs")
pico_set_program_version(pico-oqs "0.1")

# Modify the below lines to enable/disable output over UART/USB
pico_enable_stdio_uart(pico-oqs 0)
pico_enable_stdio_usb(pico-oqs 1)

# Include liboqs
if(NOT DEFINED ENV{LIBOQS_PATH})
    message(FATAL_ERROR "The environment variable LIBOQS_PATH is not set")
endif()
set(LIBOQS_PATH $ENV{LIBOQS_PATH})
include_directories(${LIBOQS_PATH}/include)
link_directories(${LIBOQS_PATH}/lib)

# Add the standard library to the build
target_link_libraries(pico-oqs
        pico_stdlib)

# Add the standard include files to the build
target_include_directories(pico-oqs PRIVATE
        ${CMAKE_CURRENT_LIST_DIR}
)

# Add any user requested libraries
target_link_libraries(pico-oqs ${LIBOQS_PATH}/lib/liboqs.a)

pico_add_extra_outputs(pico-oqs)

