#include <zmq.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <assert.h>
 
int main (int argc, char** argv)
{
    void *context = zmq_ctx_new();
    void *subscriber = zmq_socket(context, ZMQ_SUB);
    int ret = zmq_ctx_set(context, ZMQ_MAX_SOCKETS, 1);/// 该环境中只允许有一个socket的存在
    assert(ret == 0);

    int err = zmq_connect(subscriber, "tcp://localhost:7766"); assert(err == 0);

    // 订阅者端必须使用函数zmq_setsockopt对消息进行滤波，否则接受不到消息。
    err = zmq_setsockopt(subscriber, ZMQ_SUBSCRIBE, "", 0); assert(err == 0);

    char buffer[16];
    while (1)
    {
        memset(buffer, 0, 16);
        zmq_recv (subscriber, buffer, 16, 0);
        printf("subscriber2 recv msg: %s\n", buffer);
    }
    
    zmq_close (subscriber);
    zmq_ctx_destroy (context);
    return 0;
}