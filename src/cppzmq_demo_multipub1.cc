#include <zmq.hpp>
#include <string>
#include <iostream>
#include <thread>
#include <chrono>

int main () {
    zmq::context_t context (1);
    zmq::socket_t socket (context, ZMQ_PUB);
    socket.bind ("tcp://*:5555");
    std::this_thread::sleep_for(std::chrono::milliseconds(200));

    for (int i=0; i<10; i++) {
        zmq::message_t msg_topic(6);
        memset(msg_topic.data(), 0, 6);
        memcpy(msg_topic.data(), "pub1", 6);
        socket.send(msg_topic, ZMQ_SNDMORE);

        zmq::message_t msg(20);
        memset(msg.data(), 0, 20);
        snprintf((char*)msg.data(), 20, "publish1 %d msg", i);
        socket.send(msg, ZMQ_DONTWAIT);
        std::cout << "publish: " << i << " msg" << std::endl;

        std::this_thread::sleep_for(std::chrono::milliseconds(200));
    }
    return 0;
}
