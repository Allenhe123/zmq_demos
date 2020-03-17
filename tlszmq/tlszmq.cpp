#include <stdexcept>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include "tlszmq.h"
#include "tlsexception.h"

TLSZmq::TLSZmq(SSL_CTX *ctx)
{
    init_(ctx);
    // 设置成客户端模式
    SSL_set_connect_state(ssl);
}

TLSZmq::TLSZmq( 
    SSL_CTX *ctx,
    const char *certificate,
    const char *key)
{
    // int rc = SSL_CTX_use_certificate_file(ctx, certificate, SSL_FILETYPE_PEM);
    // if (rc != 1) {
    //     throw TLSException("failed to read credentials.");
    // }

    // rc = SSL_CTX_use_PrivateKey_file(ctx, key, SSL_FILETYPE_PEM);
    // if (rc != 1) {
    //     throw TLSException("failed to use private key.");
    // }

    // // 判定私钥是否正确
    // if(!SSL_CTX_check_private_key(ctx))
    // {
    //     printf("SSL_CTX_check_private_key error!\n");
    //     ERR_print_errors_fp(stderr);
    // }

    init_(ctx);
    //设置成服务器模式
    SSL_set_accept_state(ssl);


    // 是否要求校验对方证书 此处不验证客户端身份所以为： SSL_VERIFY_NONE
    SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);

    // 加载CA的证书
    // if(!SSL_CTX_load_verify_locations(ctx, CA_CERT_FILE, NULL))
    // {
    //     printf("SSL_CTX_load_verify_locations error!\n");
    //     ERR_print_errors_fp(stderr);
    // }

    // 加载自己的证书 此证书用来发送给客户端。 证书里包含有公钥
    if(SSL_CTX_use_certificate_file(ctx, certificate, SSL_FILETYPE_PEM) <= 0)
    {
        printf("SSL_CTX_use_certificate_file error!\n");
        ERR_print_errors_fp(stderr);
    }

    // 加载自己的私钥  私钥的作用是，ssl握手过程中，对客户端发送过来的随机
    //消息进行加密，然后客户端再使用服务器的公钥进行解密，若解密后的原始消息跟
    //客户端发送的消息一致，则认为此服务器是客户端想要链接的服务器
    if(SSL_CTX_use_PrivateKey_file(ctx, key, SSL_FILETYPE_PEM) <= 0)
    {
        printf("SSL_CTX_use_PrivateKey_file error!\n");
        ERR_print_errors_fp(stderr);
    }

    // 判定私钥是否正确
    if(!SSL_CTX_check_private_key(ctx))
    {
        printf("SSL_CTX_check_private_key error!\n");
        ERR_print_errors_fp(stderr);
    }
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
        printf("BIO_write wrote size: %d\n", rc);
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
    // printf("send tls size:%u\n", ssl_to_zmq->size());
    return ssl_to_zmq->size() > 0;
}

zmq::message_t *TLSZmq::read() {
	if (can_recv()) {
		zmq::message_t *msg = new zmq::message_t(ssl_to_app->size());
		memcpy (msg->data(), ssl_to_app->data(), ssl_to_app->size());
		ssl_to_app->rebuild(0);
		return msg;
	} else {
        printf("ssl_to_app msessage size is 0\n");
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
    	meth = TLSv1_2_client_method();
        // meth = SSLv3_client_method();
    } else if (SSL_SERVER == mode) {
    	 meth = TLSv1_2_server_method();
        // meth = SSLv3_server_method();
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
        printf("BIO_read size: %d\n", read);
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
        // int left = SSL_pending(ssl);
        printf("ssl read sizeee: %d\n", read);
        check_ssl_(read);

        if (read > 0) {
            printf("ssl read size: %d\n", read);
            size_t cur_size = aread.length();
            aread.resize(cur_size + read);
            std::copy(readto, readto + read, aread.begin() + cur_size);
            continue;
        } else {
            if (read < 0 &&  SSL_get_error(ssl, read)  == SSL_ERROR_WANT_READ)
            {
                printf("got SSL_ERROR_WANT_READ\n");
                continue;
            }
        }

		if (SSL_ERROR_ZERO_RETURN == SSL_get_error(ssl, read) ) {
            printf("will SSL_shutdown \n");
			SSL_shutdown(ssl);
		}
        break;
    }
    
    if (!aread.empty()) {
        ssl_to_app->rebuild(aread.length());
        memcpy(ssl_to_app->data(), aread.c_str(), aread.length());
    }
    printf("after need read size: %d\n", aread.size());
}

void TLSZmq::check_ssl_(int rc) {
    int err = SSL_get_error(ssl, rc);

    if (err == SSL_ERROR_NONE || err == SSL_ERROR_WANT_READ) {
        return;
    }

    if (err == SSL_ERROR_SYSCALL || err == SSL_ERROR_SSL) {
        printf("will throw exception\n");
        throw TLSException(err);
    }
    return;
}

void TLSZmq::show_certs() {
    X509 *cert;
    char *line;
    cert = SSL_get_peer_certificate(ssl);
    if (cert != NULL)
    {
        printf("数字证书信息:\n");
        line = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
        printf("证书: %s\n", line);
        free(line);
        line = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);
        printf("颁发者: %s\n", line);
        free(line);
        X509_free(cert);
    }
    else
        printf("无证书信息！\n");
}