#include <zmq.hpp>
#include <string>
#include <iostream>

int main () {
    zmq::context_t context (1);
    zmq::socket_t socket (context, ZMQ_SUB);
    //设置订阅主题
    socket.setsockopt(ZMQ_SUBSCRIBE, "pub1", 4);
    socket.setsockopt(ZMQ_SUBSCRIBE, "pub2", 4);
    socket.connect("tcp://localhost:5555");
    socket.connect("tcp://localhost:6666");

    for (;;) {
        zmq::message_t topic;
        socket.recv(topic);
        // std::cout << "sub1-recv topic: " << topic << std::endl;

        zmq::message_t msg;
        socket.recv(msg);
        std::cout << "sub-recv: " << msg << std::endl;
    }
    return 0;
}
