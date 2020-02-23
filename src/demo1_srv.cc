// 服务端代码
#include <zmq.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <assert.h>

int main (int argc, char** argv)
{
    // Socket to talk to clients
    void *context = zmq_ctx_new ();
    void *responder = zmq_socket (context, ZMQ_REP);
    
    int recv_time_out = 5000;// millsecond
    int rc = zmq_setsockopt(responder, ZMQ_RCVTIMEO, &recv_time_out, sizeof(recv_time_out));
    assert (rc == 0);

    // 如果用ipc的话，需要touch创建/tmp/feeds/0这个文件
    const char* ipc = "ipc:///tmp/feeds/0";
    rc = zmq_bind (responder, ipc);
    // rc = zmq_bind (responder, "tcp://*:7766");
    assert (rc == 0);
    zmq_sleep(1);
 
    char buffer[16];
    while (true)
    {
        memset(buffer, 0, 16);
        zmq_recv (responder, buffer, 16, 0);
        zmq_send (responder, "iamserver", 9, 0);
        printf("sever_receive: %s\n",buffer);
        usleep (1000); // Do some 'work'
    }

    zmq_close (responder);
    zmq_ctx_destroy (context);

    return 0;
}