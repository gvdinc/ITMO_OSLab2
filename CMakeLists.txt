cmake_minimum_required(VERSION 3.27)
project(KernelModule)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

# Find the kernel release
execute_process(
        COMMAND uname -r
        OUTPUT_VARIABLE KERNEL_RELEASE
        OUTPUT_STRIP_TRAILING_WHITESPACE
)

# Find the headers
find_path(
        KERNELHEADERS_DIR
        include/linux/user.h
        PATHS /usr/src/linux-headers-${KERNEL_RELEASE}
)

message(STATUS "Kernel release: ${KERNEL_RELEASE}")
message(STATUS "Kernel headers: ${KERNELHEADERS_DIR}")

# Add header files
include_directories(
        ${KERNELHEADERS_DIR}/include
)

# Исходники модуля
set(SOURCE_FILES Source/Kernel/main.c
        .local-cash/Test/magister.c
        Source/Kernel/stats/cpustats.c
        Source/Kernel/stats/cpustats.h)
# Добавление цели модуля ядра
add_library(stats_module SHARED ${SOURCE_FILES})

# Указываем, что это модуль ядра
set_target_properties(stats_module PROPERTIES PREFIX "" SUFFIX ".ko")

target_compile_options(stats_module PRIVATE
#        #-print-prog-name=ld # https://stackoverflow.com/questions/37771339/sys-types-h-no-such-file-or-directory
        -fno-pie            # https://askubuntu.com/questions/851433/kernel-doesnt-support-pic-mode-for-compiling
        -Wall
        -Wextra
        -Werror
        -nostdinc
#        -fno-strict-aliasing
#        -fno-common
#        -fno-builtin
#        -nostdlib
#        -mno-red-zone
#        -mcmodel=kernel
#        -fno-stack-protector
#        -Wno-unused-function
#        -Wno-unused-variable
#        -Wno-unused-label
#        -Wno-unused-value
#        -Wno-unused-parameter
#        -Wno-unused-result
)






## Исходники модуля
#set(SOURCE_FILES Source/Kernel/Kernel-module.c)
#
## Добавление цели модуля ядра
#add_library(stats_module SHARED ${SOURCE_FILES})
#
## Связывание с ядром
#target_include_directories(stats_module PRIVATE
#        /usr/src/${KERNEL_VERSION}/include
#        ${KERNEL_DIR}/arch/x86/include
#        ${KERNEL_DIR}/arch/x86/include/generated
#        ${KERNEL_DIR}/include
#)
#
## Дополнительные флаги компилятора
#target_compile_options(stats_module PRIVATE
#        #-print-prog-name=ld # https://stackoverflow.com/questions/37771339/sys-types-h-no-such-file-or-directory
#        -fno-pie            # https://askubuntu.com/questions/851433/kernel-doesnt-support-pic-mode-for-compiling
#        -Wall
#        -Wextra
#        -Werror
#        -nostdinc
#        -fno-strict-aliasing
#        -fno-common
#        -fno-builtin
#        -nostdlib
#        -mno-red-zone
#        -mcmodel=kernel
#        -fno-stack-protector
#        -Wno-unused-function
#        -Wno-unused-variable
#        -Wno-unused-label
#        -Wno-unused-value
#        -Wno-unused-parameter
#        -Wno-unused-result
#)
#
## Указываем, что это модуль ядра
#set_target_properties(stats_module PROPERTIES PREFIX "" SUFFIX ".ko")
#
## Установка модуля в систему
#add_custom_target(install_module
#        COMMAND sudo insmod $<TARGET_FILE:stats_module>
#        DEPENDS stats_module
#        COMMENT "Installing kernel module"
#)
#
## Удаление модуля из системы
#add_custom_target(uninstall_module
#        COMMAND sudo rmmod stats_module
#        COMMENT "Removing kernel module"
#)
# Phase 1
#target_include_directories(stats_module PRIVATE
#        /usr/src/${KERNEL_VERSION}/include
#        ${KERNEL_DIR}/arch/x86/include
#        ${KERNEL_DIR}/arch/x86/include/generated
#        ${KERNEL_DIR}/include
#)