#include <zmq.hpp>
#include <string>
#include <iostream>

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

int main () {
    zmq::context_t context (1);
    zmq::socket_t socket (context, ZMQ_SUB);
    //设置订阅主题
    socket.setsockopt(ZMQ_SUBSCRIBE, "topic", 5);
    socket.connect("tcp://localhost:5555");

    for (;;) {
        static double time_sum = 0;
        static uint32_t count = 1;

        zmq::message_t topic;
        socket.recv(topic);

        zmq::message_t msg;
        socket.recv(msg);

        uint64_t send_time = string_to_uint64((char*)msg.data());
        uint64_t delta = Now() - send_time;
        double deltatime = (double)delta / 1000000.0f; // millsecond 
        time_sum += deltatime;
        std::cout << "delta-time: " << deltatime << " count: " << count << std::endl;
        if (count == 128) {
            std::cout << "average delta-time: " << time_sum / count << std::endl;
        }
        count++;
    }
    return 0;
}
