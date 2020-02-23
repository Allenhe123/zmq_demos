#include <zmq.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <assert.h>
 
int main (int argc, char** argv)
{
    void *context = zmq_ctx_new();
    void *publisher = zmq_socket(context, ZMQ_PUB);

    int ret = zmq_ctx_set(context, ZMQ_MAX_SOCKETS, 1);/// 在该环境中最大只允许一个socket存在
    assert(ret == 0);

    int err = zmq_bind(publisher, "tcp://*:7766");
    if (err != 0) {
        printf("zmq connect error.\n");
        return -1;
    }

    for (int i=0; i<10; i++)
    {
        zmq_send(publisher, "iampublisher", 12, 0);
        printf("publish idx: %d\n", i);
        zmq_sleep(1);
    }
    zmq_close (publisher);
    zmq_ctx_destroy (context);
    return 0;
}