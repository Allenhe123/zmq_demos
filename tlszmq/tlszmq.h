/*
 * Quick and dirty class to wrap data in TLS for use over ZeroMQ
 * Based on code from http://funcptr.net/2012/04/08/openssl-as-a-filter-%28or-non-blocking-openssl%29/
 */

#ifndef _TLSZMQ_H
#define _TLSZMQ_H

#include <openssl/ssl.h>
#include <zmq.hpp>

/*
send:  app_to_ssl  --> ssl_to_zmq  --> ....
recv:  zmq_to_ssl  --> ssl_to_app  --> ....

openssl可以使用SSL和BIO两种方式实现SSL，如果使用BIO方式，那么就是上面说的这一种，
最终的IO是要调用BIO_write和 BIO_read来进行的，用BIO实现的ssl关键在于在io之前必须
设置好套接字BIO和ssl类型的BIO以及SSL结构体之间的联系，这是通过 BIO_set_ssl和BIO_push来实现的。 

SSL层设置为在缓冲模式下工作.因此,执行SSL_write意味着我们将未加密的字节发送到SSL库,
以便它可以加密这些字节并将生成的加密字节放入缓冲区.然后我们从缓冲区读取使用BIO_read.
反向读取相同的东西.在这种情况下,我们实际上做了BIO_write然后是SSL_read.
*/

class TLSZmq {
    public:
	enum {SSL_CLIENT = 0, SSL_SERVER = 1};
	static SSL_CTX *ssl_ctx;
	static SSL_CTX *init_ctx(int mode);

        TLSZmq(SSL_CTX *ctx);
        TLSZmq( SSL_CTX *ctx, const char *certificate, const char *key);
        virtual ~TLSZmq();

        bool can_recv();
        bool needs_write();
        
        zmq::message_t *read();
        void write(zmq::message_t *msg);

        zmq::message_t *get_data();
        void put_data(zmq::message_t *msg);

        void shutdown();
        void show_certs();

    private:
        void init_(SSL_CTX *ctxt);
        void update();
        void check_ssl_(int ret_code);
        void net_read_();
        void net_write_();

        SSL * ssl;
        BIO * rbio;
        BIO * wbio;
        
        zmq::message_t *app_to_ssl;
        zmq::message_t *ssl_to_app;
        zmq::message_t *ssl_to_zmq;
        zmq::message_t *zmq_to_ssl;
};

#endif /* _TLSZMQ_H */
