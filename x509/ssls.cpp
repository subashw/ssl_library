#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <pthread.h>
#include <openssl/ssl.h>
#include <openssl/crypto.h>
#include <poll.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/rand.h>

#include <event2/event.h>
#include <event2/listener.h>
#include <event2/bufferevent_ssl.h>

#include <x509.hpp>
#include <ca.hpp>
#include <ini.h>
#include <stream.h>

#include "qmgmt.hpp"
#include "x509.hpp"
#include "ca.hpp"

using namespace std;

pthread_mutex_t *SSLServer::_ssl_locks = NULL;
int SSLServer::_ssl_num_locks = 0;
bool SSLServer::_doneInit = false;
//A::FPTR A::cb = NULL;
VERIFY_CALLBACK SSLServer::_verifyCallback = NULL;
uint8_t SSLServer::_cookie_secret[COOKIE_SECRET_LENGTH] = {0};
int SSLServer::_cookie_initialized = 0;

#define MATCH(s, n) strcasecmp(section, s) == 0 && strcasecmp(name, n) == 0

/* Implements a thread-ID function as requied by openssl */
unsigned long SSLServer::get_thread_id_cb(void)
{
    return (unsigned long)pthread_self();
}

void SSLServer::thread_lock_cb(int mode, int which, const char * f, int l)
{
    if (which < _ssl_num_locks) 
	{
        if (mode & CRYPTO_LOCK) 
            pthread_mutex_lock(&(_ssl_locks[which]));
		else 
            pthread_mutex_unlock(&(_ssl_locks[which]));
    }
}

int SSLServer::init_ssl_locking(void)
{
    int i;

    _ssl_num_locks = CRYPTO_num_locks();
    _ssl_locks = (pthread_mutex_t *)malloc(_ssl_num_locks * sizeof(pthread_mutex_t));
    if (_ssl_locks == NULL)
        return -1;

    for (i = 0; i < _ssl_num_locks; i++) 
        pthread_mutex_init(&(_ssl_locks[i]), NULL);

    CRYPTO_set_id_callback(SSLServer::get_thread_id_cb);
    CRYPTO_set_locking_callback(SSLServer::thread_lock_cb);

    return 0;
}

void SSLServer::Init()
{
	if (_doneInit)
	{
		_cookie_secret[0] = 0;
		_cookie_initialized = 0;
		return;
	}

	InitCrypto();

	/* Initialize the OpenSSL library */
	SSL_load_error_strings();
	SSL_library_init();
	SSL_load_error_strings();
	/* We MUST have entropy, or else there's no point to crypto. */
	RAND_poll();

	init_ssl_locking();

	_doneInit = true;
}

void SSLServer::ssl_readcb(struct bufferevent *bev, void * arg)
{
	SSLServer *ss = (SSLServer *)arg;

	if (ss)
		ss->HandleIncomingData(bev);
}

void SSLServer::ssl_eventcb(struct bufferevent *bev, short events, void *arg)
{
	SSLServer *ss = (SSLServer *)arg;
	SSL *s = bufferevent_openssl_get_ssl(bev);
	if (ss && s)
	{
		if (events & BEV_EVENT_CONNECTED)
		{
			int doStart = ss->SessionStart(s);
			if (!doStart)
			{
				printf("Closing SSL session\n");
				SSL_set_shutdown(s, SSL_SENT_SHUTDOWN|SSL_RECEIVED_SHUTDOWN);
				SSL_shutdown(s);
				printf("Closed SSL session\n");
				printf("Freeing bufferevent\n");
				bufferevent_free(bev);
				printf("Freed buffer event\n");
			}
		}
		else
			ss->HandleConnectionEvents(s, events, bev);
	}
}

void SSLServer::ssl_acceptcb(struct evconnlistener *serv, int sock, struct sockaddr *sa, int sa_len, void *arg)
{
	SSLServer *s = (SSLServer *)arg;
	s->AcceptNewConnection(sock, sa, sa_len);
}

void *SSLServer::SSLServerDispatchThread(void *arg)
{
	SSLServer *s = (SSLServer *)arg;
	s->Dispatch();
	return NULL;
}

void *SSLServer::SSLServerUDPThread(void *arg)
{
	SSLServer *s = (SSLServer *)arg;
	s->SSLUDPLoop();
	return NULL;
}

void SSLServer::SetVerifyCallback(int (*verifyCallback)(int, X509_STORE_CTX *))
{
	_verifyCallback = verifyCallback;
}

int SSLServer::GenerateCookieCallback(SSL *ssl, unsigned char *cookie, unsigned int *cookie_len)
{
    unsigned char *buffer, result[64];
    unsigned int length, resultlength;
    union {
        struct sockaddr sa;
        struct sockaddr_in s4;
        struct sockaddr_in6 s6;
    } peer;

    /* Initialize a random secret */
    if (!_cookie_initialized)
	{
        if (RAND_bytes(_cookie_secret, COOKIE_SECRET_LENGTH) <= 0) 
            return 0;
        _cookie_initialized = 1;
    }

    /* Read peer information */
    (void)BIO_dgram_get_peer(SSL_get_rbio(ssl), &peer);

    /* Create buffer with peer's address and port */
    length = 0;
    switch (peer.sa.sa_family) 
	{
		case AF_INET:
			length += sizeof(struct in_addr);
			length += sizeof(peer.s4.sin_port);
			break;

		case AF_INET6:
			length += sizeof(struct in6_addr);
			length += sizeof(peer.s6.sin6_port);
			break;

		default:
			OPENSSL_assert(0);
			break;
	}
	buffer = (uint8_t *)OPENSSL_malloc(length);

    if (buffer == NULL) 
        return 0;

	switch (peer.sa.sa_family) 
	{
		case AF_INET:
			memcpy(buffer, &peer.s4.sin_port, sizeof(peer.s4.sin_port));
			memcpy(buffer + sizeof(peer.s4.sin_port), &peer.s4.sin_addr, sizeof(struct in_addr));
			break;

		case AF_INET6:
			memcpy(buffer, &peer.s6.sin6_port, sizeof(peer.s6.sin6_port));
			memcpy(buffer + sizeof(peer.s6.sin6_port), &peer.s6.sin6_addr, sizeof(struct in6_addr));
			break;

		default:
			OPENSSL_assert(0);
			break;
	}

    /* Calculate HMAC of buffer using the secret */
    HMAC(EVP_sha1(), _cookie_secret, COOKIE_SECRET_LENGTH, buffer, length, result, &resultlength);
    OPENSSL_free(buffer);

    memcpy(cookie, result, resultlength);
    *cookie_len = resultlength;

    return 1;
}

int SSLServer::VerifyCookieCallback(SSL *ssl, unsigned char *cookie, unsigned int cookie_len)
{
    unsigned char *buffer, result[64];
    unsigned int length, resultlength;
    union {
        struct sockaddr sa;
        struct sockaddr_in s4;
        struct sockaddr_in6 s6;
    } peer;

    /* If secret isn't initialized yet, the cookie can't be valid */
    if (!_cookie_initialized)
        return 0;

    /* Read peer information */
    (void)BIO_dgram_get_peer(SSL_get_rbio(ssl), &peer);

    /* Create buffer with peer's address and port */
    length = 0;
	switch (peer.sa.sa_family) 
	{
		case AF_INET:
			length += sizeof(struct in_addr);
			length += sizeof(peer.s4.sin_port);
			break;

		case AF_INET6:
			length += sizeof(struct in6_addr);
			length += sizeof(peer.s6.sin6_port);
			break;

		default:
			OPENSSL_assert(0);
			break;
	}
    buffer = (uint8_t *)OPENSSL_malloc(length);

    if (buffer == NULL) 
        return 0;

    switch (peer.sa.sa_family) 
	{
		case AF_INET:
			memcpy(buffer, &peer.s4.sin_port, sizeof(peer.s4.sin_port));
			memcpy(buffer + sizeof(peer.s4.sin_port), &peer.s4.sin_addr, sizeof(struct in_addr));
			break;

		case AF_INET6:
			memcpy(buffer, &peer.s6.sin6_port, sizeof(peer.s6.sin6_port));
			memcpy(buffer + sizeof(peer.s6.sin6_port), &peer.s6.sin6_addr, sizeof(struct in6_addr));
			break;

		default:
			OPENSSL_assert(0);
			break;
	}

    /* Calculate HMAC of buffer using the secret */
    HMAC(EVP_sha1(), _cookie_secret, COOKIE_SECRET_LENGTH, buffer, length, result, &resultlength);
    OPENSSL_free(buffer);

    if (cookie_len == resultlength && memcmp(result, cookie, resultlength) == 0)
        return 1;

    return 0;
}

int SSLServer::VerifyCallback(int ok, X509_STORE_CTX *x509_ctx)
{
	int depth = X509_STORE_CTX_get_error_depth(x509_ctx);
	int err  = X509_STORE_CTX_get_error(x509_ctx);
	X509 *cert = X509_STORE_CTX_get_current_cert(x509_ctx);
	STACK_OF(X509) *certstack = X509_STORE_CTX_get1_chain(x509_ctx);
	if (certstack == NULL)
	{
		printf("=============Error in cert stack=============\n");
		return ok;
	}
	int verifyDepth = sk_X509_num(certstack);
	int issuerDepth;
	if (depth+1 == verifyDepth)
		issuerDepth=depth;
	else
		issuerDepth=depth+1;

	X509 *issuerCert = sk_X509_value(certstack, issuerDepth);
	if (issuerCert == NULL)
	{
		printf("=============Error in cert stack_issuerCert=============\n");
		sk_X509_pop_free(certstack, X509_free);
		return ok;
	}

	CX509Certificate myCert;
	CX509Certificate caCert;

	myCert.SetCertificate(cert);
	caCert.SetCertificate(issuerCert);

	ok = myCert.VerifyCA(caCert);
	sk_X509_pop_free(certstack, X509_free);

	if (ok)
	{
		if (SSLServer::_verifyCallback)
			ok = SSLServer::_verifyCallback(ok,x509_ctx);
	}

	return ok;
}

void SSLServer::SSLUDPLoop()
{
    int i;

	struct pollfd fds[1];

	fds[0].fd = _udpSocket;
	fds[0].events = POLLIN|POLLERR|POLLHUP;

	while (!_terminate)
	{
        int read_from_sslcon;

        read_from_sslcon = SSL_pending(_udpSSL);

        if (!read_from_sslcon) 
		{
			fds[0].revents = 0;
			i = poll(fds, 1, 1000);
			if (i < 0)
			{
				printf("Poll Error\n");
				break;
			}
			else if (i == 0)
			{
				_udpTimeout++;
				if (_udpTimeout > MAX_TIMEOUT)
				{
					printf("Timeout reached\n");
					pthread_mutex_lock(&_timeoutMutex);
					pthread_cond_signal(&_timeoutCond);
					pthread_mutex_unlock(&_timeoutMutex);
				}
				continue;
			}
			else
			{
				_udpTimeout = 0;
				read_from_sslcon = 1;
			}
        }

        if (read_from_sslcon) 
		{
            if (!SSL_is_init_finished(_udpSSL)) 
			{
    			i = SSL_accept(_udpSSL);

                if (i <= 0)
				{
        			if (BIO_sock_should_retry(i)) 
						continue;
					_terminate = true;
					break;
                }
				else
					printf("Handshake done\n");
            } 
			else 
			{
 again:
    			uint8_t buf[16384];

                i = SSL_read(_udpSSL, (char *)buf, sizeof(buf));
                switch (SSL_get_error(_udpSSL, i)) 
				{
					case SSL_ERROR_NONE:
						buf[i] = 0;
						printf("%s", (char *)buf);
						if (this->_jobUDP)
							this->_jobUDP(_userData, buf, i);
						if (SSL_pending(_udpSSL))
							goto again;
						break;

					case SSL_ERROR_WANT_WRITE:
					case SSL_ERROR_WANT_READ:
						break;

					case SSL_ERROR_SYSCALL:
					case SSL_ERROR_SSL:
					case SSL_ERROR_ZERO_RETURN:
						printf("Socket closed\n");
						_terminate = true;
						break;
				}
			}
		}
	}

	SSL_set_shutdown(_udpSSL, SSL_SENT_SHUTDOWN|SSL_RECEIVED_SHUTDOWN);
    SSL_shutdown(_udpSSL);
    SSL_free(_udpSSL);
	_udpSSL = NULL;
	_udpSbio = NULL;
}

bool SSLServer::UDPSSLRead(uint8_t *data, int sz, int *bytes)
{
	bool rv = false;
   	uint8_t buf[16384];
	int i;

    i = SSL_read(_udpSSL, (char *)data, sz);
    switch (SSL_get_error(_udpSSL, i)) 
	{
		case SSL_ERROR_NONE:
			rv = true;
			*bytes = i;
			break;

		case SSL_ERROR_WANT_WRITE:
		case SSL_ERROR_WANT_READ:
			*bytes = 0;
			break;

		case SSL_ERROR_SYSCALL:
		case SSL_ERROR_SSL:
		case SSL_ERROR_ZERO_RETURN:
			*bytes = -1;
			break;
	}
	_udpTimeout = 0;

	return rv;
}

void SSLServer::HandleIncomingData(struct bufferevent *bev)
{
	struct evbuffer *in = bufferevent_get_input(bev);
	SSL *s = bufferevent_openssl_get_ssl(bev);
	if (s && in)
	{
		if (this->_job)
		{
			WaitingPayload *wp = new WaitingPayload(in, s, bev, _userData, this->_job);
			if (wp)
				WaitingPayload::AddToWaitingJobs(wp);
		}
	}
}

int SSLServer::SessionStart(SSL *ssl)
{
	int rv = 1;

	if (_sessionStartCallback)
		rv = this->_sessionStartCallback(ssl, _userData);

	return rv;
}

void SSLServer::HandleConnectionEvents(SSL *s, short events, struct bufferevent *bev)
{
	int theEvent;

	if (events & BEV_EVENT_EOF)
	{
		printf("Socket closed EOF\n");
		theEvent = BEV_EVENT_EOF;
	}
	else if (events & BEV_EVENT_READING)
	{
		printf("Socket error ERR Reading\n");
		theEvent = BEV_EVENT_READING;
	}
	else if (events & BEV_EVENT_WRITING)
	{
		printf("Socket error ERR Writing\n");
		theEvent = BEV_EVENT_WRITING;
	}
	else if (events & BEV_EVENT_ERROR)
	{
		printf("Socket error ERR Unknown\n");
		theEvent = BEV_EVENT_ERROR;
	}
	else if (events & BEV_EVENT_TIMEOUT)
	{
		printf("Socket error ERR Timeout\n");
		theEvent = BEV_EVENT_TIMEOUT;
	}

	bool doFinish = true;
	if (_sessionEndCallback)
		doFinish = this->_sessionEndCallback(s, _userData);

	if (doFinish)
	{
		printf("Closing SSL session\n");
		SSL_set_shutdown(s, SSL_SENT_SHUTDOWN|SSL_RECEIVED_SHUTDOWN);
		SSL_shutdown(s);
		printf("Closed SSL session\n");
		printf("Freeing bufferevent\n");
		bufferevent_free(bev);
		printf("Freed buffer event\n");
	}
}

void SSLServer::AcceptNewConnection(int sock, struct sockaddr *sa, int sa_len)
{
	if (_mode != SOCKET_MODE_TCP)
		return;

   	struct bufferevent *bev = NULL;

   	SSL *ssl = SSL_new(_server_ctx);
	if (ssl == NULL)
		return;

	bool accepted = false;

	bev = bufferevent_openssl_socket_new(_evbase, sock, ssl, BUFFEREVENT_SSL_ACCEPTING, BEV_OPT_CLOSE_ON_FREE);
	if (bev != NULL)
	{
		accepted = true;
	   	bufferevent_enable(bev, EV_READ|EV_PERSIST);
   		bufferevent_setcb(bev, SSLServer::ssl_readcb, NULL, SSLServer::ssl_eventcb, this);
		if (_newClientCallback)
			accepted = this->_newClientCallback(sa, sa_len, _userData);
	}

	if (!accepted)
	{
		printf("Closing SSL session\n");
		SSL_set_shutdown(ssl, SSL_SENT_SHUTDOWN|SSL_RECEIVED_SHUTDOWN);
		SSL_shutdown(ssl);
		printf("Closed SSL session\n");
		printf("Freeing bufferevent\n");
		bufferevent_free(bev);
		printf("Freed buffer event\n");
//		printf("Freeing SSL session\n");
//		SSL_free(ssl);
//		printf("Freed SSL session\n");
	}
}

bool SSLServer::WriteBufferSSL(SSL *s, uint8_t *buf, int length)
{
	bool rv = false;

tryAgain:
	int num = SSL_write(s, buf, length);
	if (num > 0)
	{
		if (num == length) 
			rv = true;
	}
	else if (num == 0)
	{
		int ssl_error = SSL_get_error(s, num);
		if (ssl_error == SSL_ERROR_WANT_WRITE)
			goto tryAgain;
		long error = ERR_get_error();
		const char* error_str = ERR_error_string(error, NULL);
		printf("could not SSL_write (returned 0): %s\n", error_str);
	}
	else if (num < 0)
	{
		int ssl_error = SSL_get_error(s, num);
		if (ssl_error == SSL_ERROR_WANT_WRITE)
			goto tryAgain;
	}

	return rv;
}

bool SSLServer::WriteBufferSSL(uint8_t *buf, int length)
{
	bool rv = false;

	_udpTimeout = 0;
tryAgain:
	int num = SSL_write(_udpSSL, buf, length);
	if (num > 0)
	{
		if (num == length) 
			rv = true;
	}
	else if (num == 0)
	{
		int ssl_error = SSL_get_error(_udpSSL, num);
		if (ssl_error == SSL_ERROR_WANT_WRITE)
			goto tryAgain;
		long error = ERR_get_error();
		const char* error_str = ERR_error_string(error, NULL);
		printf("could not SSL_write (returned 0): %s\n", error_str);
	}
	else if (num < 0)
	{
		int ssl_error = SSL_get_error(_udpSSL, num);
		if (ssl_error == SSL_ERROR_WANT_WRITE)
			goto tryAgain;
	}

	return rv;
}

void SSLServer::Dispatch()
{
//	while (!_terminate)
//	{
//		event_base_loop(_evbase, EVLOOP_NONBLOCK);
//	}
	event_base_dispatch(_evbase);
}

bool SSLServer::Valid()
{
	return _valid;
}

SSLServer::~SSLServer()
{
	if (_valid)
	{
		void *ret;

		if (_mode == SOCKET_MODE_TCP)
		{
			_terminate = true;
			pthread_join(_dispatchThread, &ret);
		}
		else if (_mode == SOCKET_MODE_UDP)
		{
			_terminate = true;
			pthread_join(_dispatchThread, &ret);
		}
	}

	if (_server_ctx)
		SSL_CTX_free(_server_ctx);

	if (_listener)
		evconnlistener_free(_listener);

	if (_udpSSL)
	{
		SSL_set_shutdown(_udpSSL, SSL_SENT_SHUTDOWN|SSL_RECEIVED_SHUTDOWN);
		SSL_shutdown(_udpSSL);
		SSL_free(_udpSSL);
	}

	if (_evbase)
		event_base_free(_evbase);

	if (_udpSocket != -1)
		close(_udpSocket);
	pthread_mutex_destroy(&_timeoutMutex);
    pthread_cond_destroy(&_timeoutCond);
}

SSLServer::SSLServer(const SSL_METHOD *method, std::string &sslCertFile, std::string &sslKeyFile, std::string &caCertFile, bool wantAuth, bool compulsory, 
	int verifyDepth, SSLSocketMode mode)
{
	_port = -1;
	_method = method;
	_wantAuth = wantAuth;
	_compulsory = compulsory;
	_verifyDepth = verifyDepth;
	_mode = mode;
	_job = NULL;
	_valid = false;
	_userData = this;
	_newClientCallback = NULL;
	_sessionEndCallback = NULL;
	_sessionStartCallback = NULL;
	_verifyCallback = NULL;
	_caCertFile = caCertFile;
	_evbase = NULL;
	_listener = NULL;
	_udpSSL = NULL;
	_terminate = false;
	_udpSocket = -1;
	_udpSbio = NULL;
	_udpTimeout = 0;
	pthread_mutex_init(&_timeoutMutex, NULL);
    pthread_cond_init(&_timeoutCond, NULL);

	if (!_doneInit)
		SSLServer::Init();
	else
	{
		if (_mode == SOCKET_MODE_UDP)
			SSLServer::Init();
	}

	_valid = InitContext(sslCertFile, sslKeyFile, wantAuth, compulsory);
}

SSLServer::SSLServer(int port, const SSL_METHOD *method, std::string &sslCertFile, std::string &sslKeyFile, std::string &caCertFile, bool wantAuth, bool compulsory, 
	int verifyDepth, SSLSocketMode mode)
{
	_port = port;
	_method = method;
	_wantAuth = wantAuth;
	_compulsory = compulsory;
	_verifyDepth = verifyDepth;
	_mode = mode;
	_job = NULL;
	_valid = false;
	_userData = this;
	_newClientCallback = NULL;
	_sessionEndCallback = NULL;
	_sessionStartCallback = NULL;
	_verifyCallback = NULL;
	_caCertFile = caCertFile;
	_evbase = NULL;
	_listener = NULL;
	_udpSSL = NULL;
	_terminate = false;
	_udpSocket = -1;
	_udpSbio = NULL;
	_udpTimeout = 0;
	pthread_mutex_init(&_timeoutMutex, NULL);
    pthread_cond_init(&_timeoutCond, NULL);

	if (!_doneInit)
		SSLServer::Init();
	else
	{
		if (_mode == SOCKET_MODE_UDP)
			SSLServer::Init();
	}

	_valid = InitContext(sslCertFile, sslKeyFile, wantAuth, compulsory);
}

bool SSLServer::Run(int sock)
{
	if (!_valid)
		return _valid;

	if ((_port == -1) && (sock == -1))
	{
		_valid = false;
		return _valid;
	}

	struct sockaddr_in sin;
	if (sock == -1)
	{
		memset(&sin, 0, sizeof(sin));
		sin.sin_family = AF_INET;
		sin.sin_port = htons((short)_port);
		sin.sin_addr.s_addr = INADDR_ANY;
	}
	else
		evutil_make_socket_nonblocking(sock);

	if (_mode == SOCKET_MODE_TCP)
	{
		_evbase = event_base_new();
		if (sock == -1)
			_listener = evconnlistener_new_bind(_evbase, SSLServer::ssl_acceptcb, (void *)this, LEV_OPT_CLOSE_ON_FREE|LEV_OPT_REUSEABLE, -1, (struct sockaddr *)&sin, sizeof(sin));
		else
			_listener = evconnlistener_new(_evbase, SSLServer::ssl_acceptcb, (void *)this, LEV_OPT_CLOSE_ON_FREE|LEV_OPT_REUSEABLE, 0, sock);
		if (_listener)
		{
			WorkerThread::Init((int)sysconf(_SC_NPROCESSORS_ONLN));
			printf("SSL Server running\n");
			if (!pthread_create(&_dispatchThread, NULL, &SSLServer::SSLServerDispatchThread, (void *)this))
				_valid = true;
		}
	}
	else if (_mode == SOCKET_MODE_UDP)
	{
		bool sockGood = true;

		if (sock != -1)
			_udpSocket = sock;
		else
		{
			_udpSocket = socket(AF_INET, SOCK_DGRAM, 0);
			if (_udpSocket != -1)
				sockGood = ::bind(_udpSocket, (struct sockaddr *)&sin, sizeof (sin)) != -1;
			else
				sockGood = false;

			if (sockGood)
			{
				int j = 1;

				evutil_make_socket_nonblocking(_udpSocket);
				setsockopt(_udpSocket, SOL_SOCKET, SO_REUSEADDR, (void *)&j, sizeof(j));
			}
		}

		if (sockGood)
		{
			printf("SSL Server running\n");
			_udpSSL = SSL_new(_server_ctx);
			if (_udpSSL)
			{
				SSL_clear(_udpSSL);
				_udpSbio = BIO_new_dgram(_udpSocket, BIO_NOCLOSE);
				BIO_ctrl(_udpSbio, BIO_CTRL_DGRAM_MTU_DISCOVER, 0, NULL);
				SSL_set_options(_udpSSL, SSL_OP_COOKIE_EXCHANGE);
				SSL_set_bio(_udpSSL, _udpSbio, _udpSbio);
				SSL_set_accept_state(_udpSSL);
				if (!pthread_create(&_dispatchThread, NULL, &SSLServer::SSLServerUDPThread, (void *)this))
					_valid = true;
			}
		}
	}

	return _valid;
}

bool SSLServer::InitContext(std::string &sslCertFile, std::string &sslKeyFile, bool wantAuth, bool compulsory)
{
	if (sslCertFile.length() && sslKeyFile.length())
	{
		_sslCert.LoadCert(sslCertFile, FORMAT_PEM);
		_sslCert.LoadKey(sslKeyFile, FORMAT_PEM);
	}
	if (_caCertFile.length())
		_caCert.LoadCert(_caCertFile, FORMAT_PEM);

	if (!_sslCert.CanVerify() || !_sslCert.CanSign())
		return false;

	if (!_caCert.CanVerify())
		return false;

	_server_ctx = SSL_CTX_new(_method);
	if (_server_ctx == NULL)
		return false;

	if (!SSL_CTX_use_certificate(_server_ctx, _sslCert.UseCertificate()))
		return false;

	if (!SSL_CTX_use_PrivateKey(_server_ctx, _sslCert.UsePrivateKey()))
		return false;

	if (!SSL_CTX_load_verify_locations(_server_ctx, _caCertFile.c_str(), NULL))
		return false;

	SSL_CTX_set_client_CA_list(_server_ctx, SSL_load_client_CA_file(_caCertFile.c_str()));
	if (_mode == SOCKET_MODE_TCP)
	{
    	SSL_CTX_set_options(_server_ctx, SSL_OP_NO_TLSv1);
    	SSL_CTX_set_options(_server_ctx, SSL_OP_NO_SSLv2);
	}
	else if (_mode == SOCKET_MODE_UDP)
	{
//    	SSL_CTX_set_options(_server_ctx, SSL_OP_NO_DTLSv1);
		SSL_CTX_set_read_ahead(_server_ctx, 1);
	}

	int verifyFlags = 0;
	uint8_t id_ctx = 1;
	if (wantAuth)
	{
		verifyFlags = SSL_VERIFY_PEER;
		if (compulsory)
			verifyFlags |= SSL_VERIFY_FAIL_IF_NO_PEER_CERT;
		SSL_CTX_set_verify(_server_ctx, verifyFlags, SSLServer::VerifyCallback);
		SSL_CTX_set_verify_depth(_server_ctx, _verifyDepth);
	}
	else
		SSL_CTX_set_verify(_server_ctx, verifyFlags, NULL);

	SSL_CTX_set_session_id_context(_server_ctx, (const uint8_t *)&id_ctx, sizeof(id_ctx));
	if (_mode == SOCKET_MODE_UDP)
	{
		SSL_CTX_set_cookie_generate_cb(_server_ctx, SSLServer::GenerateCookieCallback);
		SSL_CTX_set_cookie_verify_cb(_server_ctx, SSLServer::VerifyCookieCallback);
	}
	SSL_CTX_set_client_CA_list(_server_ctx, SSL_load_client_CA_file(_caCertFile.c_str()));

	return true;
}

void SSLServer::SetNewConnectionCallback(int (*newClientCallback)(struct sockaddr *, int, void *))
{
	_newClientCallback = newClientCallback;
}

void SSLServer::SetResponseCallback(void (*job)(WaitingPayload *wp, void *))
{
	_job = job;
}

void SSLServer::SetUDPResponseCallback(void (*job)(void *, uint8_t *, int))
{
	_jobUDP = job;
}

void SSLServer::SetSessionEndCallback(int (*sessionEndCallback)(SSL *, void *))
{
	_sessionEndCallback = sessionEndCallback;
}

void SSLServer::SetSessionStartCallback(int (*sessionStartCallback)(SSL *, void *))
{
	_sessionStartCallback = sessionStartCallback;
}

void SSLServer::SetUserData(void *ud)
{
	_userData = ud;
}

int SSLServer::SSLHandshakeDone()
{
	return SSL_is_init_finished(_udpSSL);
}

void SSLServer::Lock()
{
	pthread_mutex_lock(&_timeoutMutex);
}

void SSLServer::Wait()
{
	pthread_cond_wait(&_timeoutCond, &_timeoutMutex);
}

void SSLServer::Unlock()
{
	pthread_mutex_unlock(&_timeoutMutex);
}
