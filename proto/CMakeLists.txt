project(zmq_proto)

find_package(Protobuf REQUIRED)
message(STATUS "##Found Protobuf: ${PROTOBUF_INCLUDE_DIR} ${PROTOBUF_LIBRARIES}")
include_directories(${PROTOBUF_INCLUDE_DIR})
link_directories(${PROTOBUF_LIB_DIR})

file(GLOB ZMQ_PROTO_SRCS *.proto)
PROTOBUF_GENERATE_CPP(PROTO_SRCS1 PROTO_HDRS1 ${ZMQ_PROTO_SRCS})

include_directories(${cyber_BINARY_DIR})
message(STATUS "##cyber_binary_dir: " ${cyber_BINARY_DIR})

add_library(zmq_proto SHARED ${PROTO_SRCS1} ${PROTO_HDRS1})
target_link_libraries(zmq_proto ${Protobuf_LIBRARIES})
message(STATUS "##protobuf_library: " ${Protobuf_LIBRARIES})

message(STATUS "###PROJECT_BINARY_DIR: " ${PROJECT_BINARY_DIR})

set(CMAKE_INSTALL_LIBDIR ${PROJECT_BINARY_DIR})  # 当前目录
message(STATUS "###CMAKE_INSTALL_LIBDIR: " ${CMAKE_INSTALL_LIBDIR})
install(TARGETS zmq_proto LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR})
