#include <stdexcept>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include "tlszmq.h"
#include "tlsexception.h"

TLSZmq::TLSZmq(SSL_CTX *ctx)
{
    init_(ctx);
    SSL_set_connect_state(ssl);
}

TLSZmq::TLSZmq( 
    SSL_CTX *ctx,
    const char *certificate,
    const char *key)
{
    int rc = SSL_CTX_use_certificate_file(ctx, certificate, SSL_FILETYPE_PEM);
    if (rc != 1) {
        throw TLSException("failed to read credentials.");
    }

    rc = SSL_CTX_use_PrivateKey_file(ctx, key, SSL_FILETYPE_PEM);
    if (rc != 1) {
        throw TLSException("failed to use private key.");
    }

    init_(ctx);
    SSL_set_accept_state(ssl);
}

void TLSZmq::shutdown() {
    int ret = SSL_shutdown(ssl);
    switch (ret) {
        case 0:
            SSL_shutdown(ssl);
            break;
        case 1:
        default:
            break;
    }
}

TLSZmq::~TLSZmq() {
    SSL_free(ssl);
    ERR_free_strings();

    delete ssl_to_app;
    delete app_to_ssl;
    delete zmq_to_ssl;
    delete ssl_to_zmq;
}

void TLSZmq::update()
{
    // If we have data to recv/read, Copy the data from the ZMQ message to the memory BIO
    if (zmq_to_ssl->size() > 0) {
        // write data from zmq_to_ssl to rbio
        int rc = BIO_write(rbio, zmq_to_ssl->data(), zmq_to_ssl->size());
        zmq_to_ssl->rebuild(0);
    }
    
    // If we have app data to send/write, push it through SSL write, which will hit the memory BIO. 
    if (app_to_ssl->size() > 0) {
        // OpenSSL先对app_to_ssl进行加密，然后调用BIO_write，即调用send/write
        int rc = SSL_write(ssl, app_to_ssl->data(), app_to_ssl->size());
        check_ssl_(rc);
        if ( rc == app_to_ssl->size() ) {
        	app_to_ssl->rebuild(0);
        }
	}

    net_read_();
    net_write_();
}

bool TLSZmq::can_recv() {
    return ssl_to_app->size() > 0;
}

bool TLSZmq::needs_write() {
    printf("send tls size:%u\n", ssl_to_zmq->size());
    return ssl_to_zmq->size() > 0;
}

zmq::message_t *TLSZmq::read() {
	if (can_recv()) {
		zmq::message_t *msg = new zmq::message_t(ssl_to_app->size());
		memcpy (msg->data(), ssl_to_app->data(), ssl_to_app->size());
		ssl_to_app->rebuild(0);
		return msg;
	} else {
		return NULL;
	}
}

zmq::message_t *TLSZmq::get_data() {
    // why not return ssl_to_zmq directly?
    zmq::message_t *msg = new zmq::message_t(ssl_to_zmq->size());
    memcpy (msg->data(), ssl_to_zmq->data(), ssl_to_zmq->size());
    ssl_to_zmq->rebuild(0);
    return msg;
}

void TLSZmq::put_data(zmq::message_t *msg) {
    zmq_to_ssl->rebuild(msg->data(), msg->size(), NULL, NULL);
    update();
}

void TLSZmq::write(zmq::message_t *msg) {
    app_to_ssl->rebuild(msg->data(), msg->size(), NULL, NULL);
    update();
}

SSL_CTX *TLSZmq::init_ctx(int mode) {
    OpenSSL_add_all_algorithms();
    SSL_library_init();
    SSL_load_error_strings();
    ERR_load_BIO_strings();

    const SSL_METHOD* meth;
    if (SSL_CLIENT == mode) {
    	meth = SSLv23_client_method();
    } else if (SSL_SERVER == mode) {
    	 meth = SSLv23_server_method();
    } else {
    	throw TLSException("Error: Invalid SSL mode. Valid modes are TLSZmq::SSL_CLIENT and TLSZmq::SSL_SERVER");
    }
    //创建的SSL会话环境称为CTX
    SSL_CTX *ctxt = SSL_CTX_new(meth);
    if(!ctxt) {
        ERR_print_errors_fp(stderr);
    }
    return ctxt;
}

void TLSZmq::init_(SSL_CTX *ctxt) 
{
    ssl = SSL_new(ctxt);
    
    /*
    这个函数创建并返回一个相应的新的BIO，并根据给定的BIO_METHOD类型调用BIO_set()函数给BIO结构的method成员赋值，
    如果创建或给method赋值失败，则返回NULL。创建一个Memory类型的BIO例子如下：BIO* mem=BIO_new(BIO_s_mem());
    */
    rbio = BIO_new(BIO_s_mem());
    wbio = BIO_new(BIO_s_mem());
    SSL_set_bio(ssl, rbio, wbio);
    
    ssl_to_app = new zmq::message_t(0);
    app_to_ssl = new zmq::message_t(0);
    zmq_to_ssl = new zmq::message_t(0);
    ssl_to_zmq = new zmq::message_t(0);
}

void TLSZmq::net_write_() {
    std::string nwrite;
    // Read any data to be written to the network from the memory BIO
    while (1) {
        char readto[1024];
        int read = BIO_read(wbio, readto, 1024);

        if (read > 0) {
            size_t cur_size = nwrite.length();
            nwrite.resize(cur_size + read);
            std::copy(readto, readto + read, nwrite.begin() + cur_size);
        } 

        if (read != 1024) break;
    }
    
    if (!nwrite.empty()) {
        ssl_to_zmq->rebuild(nwrite.length());
        memcpy(ssl_to_zmq->data(), nwrite.c_str(), nwrite.length());
    }
}

void TLSZmq::net_read_() {
    std::string aread;
    // Read data for the application from the encrypted connection and 
    // place it in the string for the app to read
    while (1) {
        char readto[1024];
        int read = SSL_read(ssl, readto, 1024);
        check_ssl_(read);

        if (read > 0) {
            size_t cur_size = aread.length();
            aread.resize(cur_size + read);
            std::copy(readto, readto + read, aread.begin() + cur_size);
            continue;
        }

		if (SSL_ERROR_ZERO_RETURN == SSL_get_error(ssl, read) ) {
			SSL_shutdown(ssl);
		}
        break;
    }
    
    if (!aread.empty()) {
        ssl_to_app->rebuild(aread.length());
        memcpy(ssl_to_app->data(), aread.c_str(), aread.length());
    }
}

void TLSZmq::check_ssl_(int rc) {
    int err = SSL_get_error(ssl, rc);

    if (err == SSL_ERROR_NONE || err == SSL_ERROR_WANT_READ) {
        return;
    }

    if (err == SSL_ERROR_SYSCALL || err == SSL_ERROR_SSL) {
        throw TLSException(err);
    }
    return;
}
