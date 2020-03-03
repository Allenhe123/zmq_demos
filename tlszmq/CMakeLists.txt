cmake_minimum_required(VERSION 2.8)

project(zmq-demo)

include_directories(${CMAKE_BINARY_DIR})
message(STATUS "##CMAKE_BINARY_DIR: " ${CMAKE_BINARY_DIR})
#include_directories
include_directories(${PROJECT_BINARY_DIR}/cyberRT)


# find gflags
find_package(ZeroMQ REQUIRED)
if (NOT ZeroMQ_FOUND)
    message(FATAL_ERROR "ZeroMQ not found")
else()
    message(STATUS "ZeroMQ include dir: " ${ZeroMQ_INCLUDE_DIRS})
    message(STATUS "ZeroMQ lib dir: " ${ZeroMQ_LIBS})
endif(NOT ZeroMQ_FOUND)
include_directories(${ZeroMQ_INCLUDE_DIRS})


# find openssl
find_package(openssl REQUIRED)
if (NOT openssl_FOUND)
    message(FATAL_ERROR "openssl not found")
else()
    message(STATUS "openssl include dir: " ${openssl_INCLUDE_DIRS})
    message(STATUS "openssl lib dir: " ${openssl_LIBS})
endif(NOT openssl_FOUND)
message(STATUS ${openssl_INCLUDE_DIRS})
include_directories(${openssl_INCLUDE_DIRS})


add_executable(device device.cpp)
target_link_libraries(device zmq ssl)

add_executable(tlszmq_srv tlsserver.cpp)
target_link_libraries(tlszmq_srv zmq ssl)

add_executable(tlszmq_client tlsclient.cpp)
target_link_libraries(tlszmq_client zmq ssl)