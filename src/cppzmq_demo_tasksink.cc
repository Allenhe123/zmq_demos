#include <zmq.hpp>
#include <string>
#include <iostream>
#include <thread>
#include <chrono>

int main () {
    zmq::context_t context (1);
    zmq::socket_t socket (context, ZMQ_PULL);
    socket.bind("tcp://*:5559");
    std::this_thread::sleep_for(std::chrono::milliseconds(1000));

    zmq::message_t notify_msg;
    socket.recv(notify_msg);
    std::cout << "recv notify msg: " << notify_msg << std::endl;

    for (;;) {
        zmq::message_t msg;
        socket.recv(msg);
        std::cout << "tasksink-recv: " << msg << std::endl;
    }
    return 0;
}
