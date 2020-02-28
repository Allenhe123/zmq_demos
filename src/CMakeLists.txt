cmake_minimum_required(VERSION 2.8)

project(zmq-demo)

include_directories(${CMAKE_BINARY_DIR})
message(STATUS "##CMAKE_BINARY_DIR: " ${CMAKE_BINARY_DIR})
#include_directories
include_directories(${PROJECT_BINARY_DIR}/cyberRT)


# find gflags
find_package(ZeroMQ REQUIRED)
message(STATUS ${ZeroMQ_INCLUDE_DIRS})
include_directories(${ZeroMQ_INCLUDE_DIRS})

add_executable(demo1_srv demo1_srv.cc)
target_link_libraries(demo1_srv zmq)

add_executable(demo1_client demo1_client.cc)
target_link_libraries(demo1_client zmq)

add_executable(cppzmq_intra_process cppzmq_intra_process.cc)
target_link_libraries(cppzmq_intra_process zmq pthread)

add_executable(publisher demo2_pub.cc)
target_link_libraries(publisher zmq)

add_executable(sub1 demo2_sub1.cc)
target_link_libraries(sub1 zmq)

add_executable(sub2 demo2_sub2.cc)
target_link_libraries(sub2 zmq)

add_executable(cppzmq_demo1 cppzmq_demo.cc)
target_link_libraries(cppzmq_demo1 zmq)

add_executable(cppzmq_srv cppzmq_demo_srv.cc)
target_link_libraries(cppzmq_srv zmq)

add_executable(cppzmq_client cppzmq_demo_client.cc)
target_link_libraries(cppzmq_client zmq)

add_executable(cppzmq_pub cppzmq_demo_pub.cc)
target_link_libraries(cppzmq_pub zmq)

add_executable(cppzmq_sub1 cppzmq_demo_sub1.cc)
target_link_libraries(cppzmq_sub1 zmq)

add_executable(cppzmq_sub2 cppzmq_demo_sub2.cc)
target_link_libraries(cppzmq_sub2 zmq)

add_executable(cppzmq_vent cppzmq_demo_taskvent.cc)
target_link_libraries(cppzmq_vent zmq)

add_executable(cppzmq_worker cppzmq_demo_taskworker.cc)
target_link_libraries(cppzmq_worker zmq)

add_executable(cppzmq_sink cppzmq_demo_tasksink.cc)
target_link_libraries(cppzmq_sink zmq)

add_executable(cppzmq_multipub1 cppzmq_demo_multipub1.cc)
target_link_libraries(cppzmq_multipub1 zmq)

add_executable(cppzmq_multipub2 cppzmq_demo_multipub2.cc)
target_link_libraries(cppzmq_multipub2 zmq)

add_executable(cppzmq_multisub cppzmq_demo_multisub.cc)
target_link_libraries(cppzmq_multisub zmq)
