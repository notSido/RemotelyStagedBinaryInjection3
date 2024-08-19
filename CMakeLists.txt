cmake_minimum_required(VERSION 3.29)
project(RemotelyStagedBinaryInjection2 C)

set(CMAKE_C_STANDARD 17)

add_executable(RemotelyStagedBinaryInjection2 main.c
        debug.h
        rc4.h
        hollow.h)

target_link_libraries(RemotelyStagedBinaryInjection2 wininet.lib)

set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -D_DEBUG")
set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -D_DEBUG")

if(CMAKE_BUILD_TYPE MATCHES Debug)
    target_compile_definitions(RemotelyStagedBinaryInjection2
 PUBLIC DEBUG=1)
elseif(CMAKE_BUILD_TYPE MATCHES Release)
    target_compile_definitions(RemotelyStagedBinaryInjection2
 PUBLIC DEBUG=0)
endif()
