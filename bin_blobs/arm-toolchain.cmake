set(CMAKE_SYSTEM_NAME Generic)
set(CMAKE_SYSTEM_PROCESSOR ARM)

set(TOOLCHAIN_PREFIX arm-none-eabi-)
set(CMAKE_C_COMPILER ${TOOLCHAIN_PREFIX}gcc)
set(CMAKE_CXX_COMPILER ${TOOLCHAIN_PREFIX}g++)
set(CMAKE_ASM_COMPILER ${TOOLCHAIN_PREFIX}gcc)

set(OBJECT_GEN_FLAGS "-Werror -Wall -ffunction-sections -fdata-sections -fomit-frame-pointer -nostartfiles -fno-exceptions")

set(CMAKE_C_FLAGS   "${OBJECT_GEN_FLAGS}" CACHE INTERNAL "C Compiler options")
set(CMAKE_CXX_FLAGS "${OBJECT_GEN_FLAGS}" CACHE INTERNAL "C++ Compiler options")
set(CMAKE_ASM_FLAGS "${OBJECT_GEN_FLAGS}" CACHE INTERNAL "ASM Compiler options")

set(CMAKE_EXE_LINKER_FLAGS "--specs=nano.specs --specs=nosys.specs" CACHE INTERNAL "Linker options")
