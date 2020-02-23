#include <zmq.hpp>
#include <string>
#include <iostream>

int main () {
    zmq::context_t context (1);
    zmq::socket_t socket (context, ZMQ_SUB);
    socket.setsockopt(ZMQ_SUBSCRIBE, "topic", 6);
    socket.connect("tcp://localhost:5555");

    for (;;) {
        zmq::message_t topic;
        socket.recv(topic);
        // std::cout << "sub2-recv topic: " << topic << std::endl;

        zmq::message_t msg;
        socket.recv(msg);
        std::cout << "sub2-recv: " << msg << std::endl;
    }
    return 0;
}
