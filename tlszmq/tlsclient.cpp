#include "tlszmq.h"
#include <zmq.hpp>

#include <memory>

void write_message(const std::unique_ptr<TLSZmq>& tls, zmq::socket_t *socket) {
    if(tls->needs_write()) {
        zmq::message_t *data = tls->get_data();
        socket->send(*data);
        printf("send tls data: %s\n", (char*)data->data());
        delete data;
    }
}

zmq::message_t *read_message(const std::unique_ptr<TLSZmq>& tls, zmq::socket_t *socket) {
	zmq::message_t response;
	socket->recv (&response);
    // recv的数据是tls加密后，需要放入tls进行解密
	tls->put_data(&response);

    if(tls->can_recv()) {
        return tls->read();
    }

    return NULL;
}

int main(int argc, char* argv[]) {
    try {
    	SSL_CTX *ssl_context = TLSZmq::init_ctx(TLSZmq::SSL_CLIENT);
        zmq::context_t ctx(1);
        zmq::socket_t s1(ctx, ZMQ_REQ);
        s1.connect ("tcp://localhost:5556");
        // TLSZmq *tls = new TLSZmq(ssl_context);

        std::unique_ptr<TLSZmq> tls = std::make_unique<TLSZmq>(ssl_context);

        bool loop = true;
        zmq::message_t request (32);
        memcpy(request.data(), "hello world!", 32);

        printf("client sending - [%s]\n",(char *)(request.data()));
        tls->write(&request);

        while (loop) {
            write_message(tls, &s1);

            zmq::message_t *data = read_message(tls, &s1);

            if (NULL != data) {
        		printf("client received - [%s]\n",(char *)(data->data()));
            	loop = false;
            }
        }

        // send shutdown to peer
		tls->shutdown();
		write_message(tls, &s1);

        // delete tls;
    }
    catch(std::exception &e) {
        printf ("An error occurred: %s\n", e.what());
        return 1;
    }
    return 0;
}
