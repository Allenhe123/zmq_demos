#include <zmq.hpp>
#include <string>
#include <iostream>
#include <thread>
#include <chrono>

int main () {
    zmq::context_t context (1);
    zmq::socket_t socket (context, ZMQ_REP);
    socket.bind ("tcp://*:5555");
    // bind后要sleep，不然对可能会丢第一帧消息
    std::this_thread::sleep_for(std::chrono::milliseconds(200));

    while (true) {
        zmq::message_t request;
        socket.recv (&request);
        std::cout << "Received Hello" << std::endl;

        //  Send reply back to client
        zmq::message_t reply(5);
        memcpy((void *) reply.data(), "World", 5);
        socket.send(reply);
    }
    return 0;
}
