#include <zmq.hpp>
#include <string>
#include <iostream>
#include <thread>
#include <chrono>
 
int main ()
{
    zmq::context_t context (1);
    zmq::socket_t socket (context, ZMQ_REQ);
    socket.connect ("tcp://localhost:5555");
 
    //  Do 10 requests, waiting each time for a response
    for (int i = 0; i != 10; i++) {
        zmq::message_t request (6);
        memcpy((void *) request.data(), "Hello", 5);
        std::cout << "Sending Hello " << i << std::endl;
        socket.send(request);

        std::this_thread::sleep_for(std::chrono::milliseconds(500));
 
        //  Get the reply.
        zmq::message_t reply;
        socket.recv(&reply);
        std::cout << "Received World " << i << std::endl;
    }
    return 0;
}
