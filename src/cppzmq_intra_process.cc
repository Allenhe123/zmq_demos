#include <zmq.hpp>
#include <string>
#include <iostream>
#include <thread>
#include <future>
#include <chrono>

uint64_t Now() {
  auto now = std::chrono::high_resolution_clock::now();
  auto nano_time_point = std::chrono::time_point_cast<std::chrono::nanoseconds>(now);
  auto epoch = nano_time_point.time_since_epoch();
  uint64_t now_nano = std::chrono::duration_cast<std::chrono::nanoseconds>(epoch).count();
  return now_nano;
}

uint64_t string_to_uint64(const std::string s)
{
    std::stringstream a;
    a << s;
    uint64_t ret = 0;
    a >> ret;
    return ret;
}

int main (int argc, char** argv)
{
    if (argc < 3) {
        std::cout << "usage: zmq_demo_xx  msgsize interval" << std::endl;
        return -1;
    }
    int32_t msgsize = std::stoi(argv[1]);
    int32_t interval = std::stoi(argv[2]);  //millsecond

    const char* addr = "inproc://#1";
    zmq::context_t context(0);
    zmq::context_t* p = &context;

    auto fut1 = std::async([addr, p]() {
        zmq::socket_t socket (*p, ZMQ_SUB);
        socket.setsockopt(ZMQ_SUBSCRIBE, "topic", 5);
        socket.connect(addr);

        while (true) {
            static double time_sum = 0;
            static uint32_t count = 1;

            zmq::message_t msg_topic;
            socket.recv (&msg_topic);

            zmq::message_t msg;
            socket.recv (&msg);

            uint64_t send_time = string_to_uint64((char*)msg.data());
            uint64_t delta = Now() - send_time;
            double deltatime = (double)delta / 1000000.0f; // millsecond 
            time_sum += deltatime;
            if (count == 128) {
                std::cout << "average delta-time: " << time_sum / count << std::endl;
            }
            std::cout << "delta-time: " << deltatime << " count: " << count << std::endl;
            count++;
        }
    });

    // auto fut2 = std::async([addr, p]() {
    //     zmq::socket_t socket (*p, ZMQ_SUB);
    //     socket.setsockopt(ZMQ_SUBSCRIBE, "topic", 5);
    //     socket.connect(addr);

    //     while (true) {
    //         zmq::message_t msg;
    //         socket.recv (&msg);
    //         std::cout << "thread2-recv: " << (char*)msg.data() << std::endl;
    //     }
    // });

    auto fut3 = std::async([addr, p, msgsize, interval]() {
        zmq::socket_t socket (*p, ZMQ_PUB);
        socket.bind (addr);
        std::this_thread::sleep_for(std::chrono::milliseconds(200));

        for (int i = 0; i < 128; i++) {
            zmq::message_t msg_topic(6);
            // memset(msg_topic.data(), 0, 6);
            memcpy(msg_topic.data(), "topic", 6);

            zmq::message_t msg(msgsize);
            memset(msg.data(), 0, msgsize);
            snprintf((char*) msg.data(), msgsize, "%llu", Now());

            socket.send(msg_topic, ZMQ_SNDMORE);
            socket.send(msg, ZMQ_DONTWAIT);

            std::cout << "pub: " << i << std::endl;

            std::this_thread::sleep_for(std::chrono::milliseconds(interval));
        }
    });

    fut1.wait();
    // fut2.wait();
    fut3.wait();

    return 0;
}
