#include <zmq.hpp>
#include <string>
#include <iostream>
#include <thread>
#include <chrono>

int main () {
    zmq::context_t context (1);
    zmq::socket_t socket (context, ZMQ_PUSH);
    socket.bind("tcp://*:5557");

    std::this_thread::sleep_for(std::chrono::milliseconds(1000));

    zmq::socket_t notify_sink_socket(context, ZMQ_PUSH);
    notify_sink_socket.connect("tcp://localhost:5559");
    zmq::message_t notify_msg(2);
    memcpy(notify_msg.data(), "0", 1);
    notify_sink_socket.send(notify_msg);
    std::cout << "send notify msg to sink sink task" << std::endl;

    for (int i=0; i<10; i++) {
        zmq::message_t msg(16);
        memset(msg.data(), 0, 16);
        snprintf((char*)msg.data(), 16, "messagee %d", i);
        socket.send(msg, ZMQ_DONTWAIT);
        std::cout << "taskvent-send: " << (char*)msg.data() << std::endl;

        std::this_thread::sleep_for(std::chrono::milliseconds(200));
    }
    return 0;
}
