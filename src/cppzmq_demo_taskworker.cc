#include <zmq.hpp>
#include <string>
#include <iostream>
#include <thread>
#include <chrono>

int main () {
    zmq::context_t context (1);
    zmq::socket_t recv_socket (context, ZMQ_PULL);
    recv_socket.connect("tcp://localhost:5557");

    zmq::socket_t send_socket(context, ZMQ_PUSH);
    send_socket.connect("tcp://localhost:5559");

    for (;;) {
        zmq::message_t msg;
        recv_socket.recv(msg);
        std::cout << "taskwork-recv: " << (char*)msg.data() << std::endl;

        std::this_thread::sleep_for(std::chrono::milliseconds(10));

        // zmq::message_t msgg;
        // msgg.copy(msg);
        send_socket.send(msg);
        std::cout << "taskwork-send: " << (char*)msg.data() << std::endl;
    }
    return 0;
}
