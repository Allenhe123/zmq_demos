#include <zmq.hpp>
#include <string>
#include <iostream>
#include <thread>
#include <chrono>
#include "video.pb.h"

int main () {
    zmq::context_t context (1);
    zmq::socket_t socket (context, ZMQ_REP);
    socket.bind ("tcp://*:5555");
    // bind后要sleep，不然对可能会丢第一帧消息
    std::this_thread::sleep_for(std::chrono::milliseconds(200));

    while (true) {
        zmq::message_t msg;
        socket.recv (&msg);
        zmq::demo::Frame frame; 
        frame.ParseFromArray(msg.data(), msg.size());
        std::cout << "srv recv Frame: " << frame.frame_id() << " " << frame.width() << " " << frame.height() << " " <<
                    frame.step() << " " << frame.address() << " " << frame.address_yuv420p() << std::endl;

        //  Send reply back to client
        zmq::message_t reply(32);
        memset(reply.data(), 0, 32);
        snprintf((char*)reply.data(), 32, "srv recv frame: %d\n", frame.frame_id());
        socket.send(reply, ZMQ_DONTWAIT);
    }
    return 0;
}
