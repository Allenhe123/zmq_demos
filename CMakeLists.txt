cmake_minimum_required(VERSION 2.8)

project(zmq-demo)

include(GNUInstallDirs)

message(STATUS ${GNUInstallDirs})

add_definitions(-std=c++17)
add_compile_options("-O3")

ADD_SUBDIRECTORY(src)
ADD_SUBDIRECTORY(tlszmq)
ADD_SUBDIRECTORY(proto)
