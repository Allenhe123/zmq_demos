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
    message(STATUS "ZeroMQ include dir: ${ZeroMQ_INCLUDE_DIR}")
    message(STATUS "ZeroMQ lib dir: ${ZeroMQ_LIBRARY}")
endif(NOT ZeroMQ_FOUND)
include_directories(${ZeroMQ_INCLUDE_DIR})

# set(openssl_DIR )

# find openssl
find_package(OpenSSL REQUIRED)
if (NOT OpenSSL_FOUND)
    message(STATUS "OpenSSL not found")
else()
    message(STATUS "OpenSSL_INCLUDE_DIR: ${OPENSSL_INCLUDE_DIR}")
    message(STATUS "OpenSSL_SSL_LIBRARY: ${OPENSSL_SSL_LIBRARY}")
endif(NOT OpenSSL_FOUND)

include_directories(${OpenSSL_INCLUDE_DIR})


add_executable(device device.cpp)
target_link_libraries(device zmq ssl crypto)

add_executable(tlszmq_srv tlsserver.cpp tlszmq.cpp tlsexception.cpp)
target_link_libraries(tlszmq_srv zmq ssl crypto)

add_executable(tlszmq_client tlsclient.cpp tlszmq.cpp tlsexception.cpp)
target_link_libraries(tlszmq_client zmq ssl crypto)