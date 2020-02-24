#include <zmq.hpp>
#include <string>
#include <iostream>
#include <thread>
#include <chrono>

uint64_t Now() {
  auto now = std::chrono::high_resolution_clock::now();
  auto nano_time_point = std::chrono::time_point_cast<std::chrono::nanoseconds>(now);
  auto epoch = nano_time_point.time_since_epoch();
  uint64_t now_nano = std::chrono::duration_cast<std::chrono::nanoseconds>(epoch).count();
  return now_nano;
}

int main (int argc, char** argv) {
    if (argc < 3) {
        std::cout << "usage: zmq_demo msgsize interval" << std::endl;
        return -1;
    }

    int32_t msgsize = std::stoi(argv[1]);
    int32_t interval = std::stoi(argv[2]);  //millsecond

    zmq::context_t context (1);
    zmq::socket_t socket (context, ZMQ_PUB);
    socket.bind ("tcp://*:5555");
    std::this_thread::sleep_for(std::chrono::milliseconds(200));

    for (int i=0; i<128; i++) {
        zmq::message_t msg_topic(6);
        memset(msg_topic.data(), 0, 6);
        memcpy(msg_topic.data(), "topic", 6);
        
        zmq::message_t msg(msgsize);
        memset(msg.data(), 0, msgsize);
        snprintf((char*) msg.data(), msgsize, "%llu", Now());

        socket.send(msg_topic, ZMQ_SNDMORE);
        socket.send(msg, ZMQ_DONTWAIT);
        std::cout << "publish: " << i << " msg" << std::endl;

        std::this_thread::sleep_for(std::chrono::milliseconds(interval));
    }
    return 0;
}
