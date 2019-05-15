cmake_minimum_required(VERSION 2.8)
project(CG)

SET(CMAKE_C_COMPILER "g++")
set(CMAKE_CXX_STANDARD 11)

ADD_DEFINITIONS(-g -W -lpthread -Wall -std=c++11 -lrt -lcrypto -lstdc++ -D_GLIBCXX_USE_CXX11_ABI=0 -fpermissive -O3)

set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -pthread")

include_directories( /usr/include)
link_libraries("/usr/lib/x86_64-linux-gnu/librt.so")
link_libraries("/usr/lib/x86_64-linux-gnu/libcrypto.a")
link_directories(/lib/x86_64-linux-gnu)

message("${CMAKE_SOURCE_DIR}")

set(SOURCE_FILES main.cpp bch.h bch.c)
add_executable(cg ${SOURCE_FILES})