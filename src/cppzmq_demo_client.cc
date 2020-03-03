#include <zmq.hpp>
#include <string>
#include <iostream>
#include <thread>
#include <chrono>
#include "video.pb.h"
 
int main ()
{
    zmq::context_t context (1);
    zmq::socket_t socket (context, ZMQ_REQ);
    socket.connect ("tcp://localhost:5555");
 
    //  Do 10 requests, waiting each time for a response
    for (int i = 1; i <= 10; i++) {
        zmq::demo::Frame frame;
        frame.set_frame_id(i);
        frame.set_height(i);
        frame.set_width(i);
        frame.set_step(i);
        frame.set_address(i);
        frame.set_address_yuv420p(i);

        char buf[64];
        frame.SerializeToArray(buf, 64);

        zmq::message_t request (strlen(buf));
        memcpy(request.data(), buf, strlen(buf));
        std::cout << "client send frame:" << i << std::endl;
        socket.send(request, ZMQ_DONTWAIT);

        // std::this_thread::sleep_for(std::chrono::milliseconds(500));
 
        //  Get the reply.
        zmq::message_t reply;
        socket.recv(&reply);
        std::cout << "client recv: " << (char*)reply.data() << std::endl;
    }
    return 0;
}
