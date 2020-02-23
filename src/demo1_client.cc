#include <zmq.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <assert.h>
 
int main (int argc, char** argv)
{
    printf ("Connecting to hello world server…\n");
    void *context = zmq_ctx_new();
    void *requester = zmq_socket(context, ZMQ_REQ);
    
    int recv_time_out = 5000;// millsecond
    int rc = zmq_setsockopt(requester, ZMQ_RCVTIMEO, &recv_time_out, sizeof(recv_time_out));
    assert(rc == 0);

    const char* ipc = "ipc:///tmp/feeds/0";
    int err = zmq_connect(requester, ipc);
    // int err = zmq_connect(requester, "tcp://localhost:7766");
    if (err != 0) {
        printf("zmq connect error.\n");
        return -1;
    }
 
    char buffer[16];
    while(true)
    {
        memset(buffer, 0, 16);
        zmq_send(requester, "iamclient", 9, 0);
        zmq_recv(requester, buffer, 16, 0);
        printf("client_receive:%s\n",buffer);
    }
    zmq_close (requester);
    zmq_ctx_destroy (context);
    return 0;
}
