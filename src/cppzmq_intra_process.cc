#include <zmq.hpp>
#include <string>
#include <iostream>
#include <thread>
#include <future>
#include <chrono>

int main (int argc, char** argv)
{
    const char* addr = "inproc://#1";
    zmq::context_t context(0);
    zmq::context_t* p = &context;

    auto fut1 = std::async([addr, p]() {
        zmq::socket_t socket (*p, ZMQ_SUB);
        socket.setsockopt(ZMQ_SUBSCRIBE, "topic", 5);
        socket.connect(addr);

        while (true) {
            zmq::message_t msg;
            socket.recv (&msg);
            std::cout << "thread1-recv: " << (char*)msg.data() << std::endl;
        }
    });

    auto fut2 = std::async([addr, p]() {
        zmq::socket_t socket (*p, ZMQ_SUB);
        socket.setsockopt(ZMQ_SUBSCRIBE, "topic", 5);
        socket.connect(addr);

        while (true) {
            zmq::message_t msg;
            socket.recv (&msg);
            std::cout << "thread2-recv: " << (char*)msg.data() << std::endl;
        }
    });

    auto fut3 = std::async([addr, p]() {
        zmq::socket_t socket (*p, ZMQ_PUB);
        socket.bind (addr);
        std::this_thread::sleep_for(std::chrono::milliseconds(200));

        for (int i = 0; i < 10; i++) {
            zmq::message_t msg_topic(6);
            memset(msg_topic.data(), 0, 6);
            memcpy(msg_topic.data(), "topic", 6);
            socket.send(msg_topic, ZMQ_SNDMORE);

            zmq::message_t msg(16);
            snprintf((char*) msg.data(), 16, "hello%d", i);
            socket.send(msg, ZMQ_DONTWAIT);
            std::cout << "pub: " << i << std::endl;

            std::this_thread::sleep_for(std::chrono::milliseconds(200));
        }
    });

    fut1.wait();
    fut2.wait();
    fut3.wait();

    return 0;
}
