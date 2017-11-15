#include <cstdlib>
#include <string>
#include <vector>

#include <sys/stat.h>
#include <sys/types.h>

#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <ctype.h>
#include <unistd.h>

#include <sys/socket.h>
#include <poll.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <pthread.h>

#include <ini.h>
#include <stream.h>

#include "qmgmt.hpp"
#include "x509.hpp"
#include "ca.hpp"

using namespace std;

#define MATCH(s, n) strcasecmp(section, s) == 0 && strcasecmp(name, n) == 0

//extern Configuration remoteClinicConf;
pthread_mutex_t *SSLClient::_ssl_locks = NULL;
int SSLClient::_ssl_num_locks = 0;
bool SSLClient::_doneInit = false;

/* Implements a thread-ID function as requied by openssl */
unsigned long SSLClient::get_thread_id_cb(void)
{
    return (unsigned long)pthread_self();
}

void SSLClient::thread_lock_cb(int mode, int which, const char * f, int l)
{
    if (which < _ssl_num_locks) 
	{
        if (mode & CRYPTO_LOCK) 
            pthread_mutex_lock(&(_ssl_locks[which]));
		else 
            pthread_mutex_unlock(&(_ssl_locks[which]));
    }
}

int SSLClient::init_ssl_locking(void)
{
    int i;

    _ssl_num_locks = CRYPTO_num_locks();
    _ssl_locks = (pthread_mutex_t *)malloc(_ssl_num_locks * sizeof(pthread_mutex_t));
    if (_ssl_locks == NULL)
        return -1;

    for (i = 0; i < _ssl_num_locks; i++) 
        pthread_mutex_init(&(_ssl_locks[i]), NULL);

    CRYPTO_set_id_callback(SSLClient::get_thread_id_cb);
    CRYPTO_set_locking_callback(SSLClient::thread_lock_cb);

    return 0;
}

void SSLClient::Init()
{
	if (_doneInit)
		return;

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

void *SSLClientThread(void *arg)
{
	SSLClient *s = (SSLClient *)arg;
	struct pollfd fds[1]; 

	s->_threadRunning = true; 
	fds[0].fd = s->_socket;
	fds[0].events = POLLIN|POLLHUP|POLLERR; 
	while (!s->_terminate)
	{
		fds[0].revents = 0; 

		int rv = poll(fds, 1, 1000);
		if (rv == -1)
			s->_terminate = true; 
		else if (rv == 0)
		{
			s->_timeout++;
			if (s->_timeout > MAX_TIMEOUT)
			{
				printf("Timeout reached\n");
				s->LockTimeout();
				s->SignalTimeout();
				s->UnlockTimeout();
			}
			continue;
		}
		else
		{
			uint8_t data[16384];
			int bytes;

			if (fds[0].revents & POLLIN)
			{
tryAgain:
				bytes = SSL_read(s->_client_ctx, data, sizeof(data));
				if (bytes < 0)
				{
					printf("SSL error=%d\n", SSL_get_error(s->_client_ctx, bytes));
					int ssl_error = SSL_get_error(s->_client_ctx, bytes);
					if (ssl_error == SSL_ERROR_WANT_READ)
						continue;
					long error = ERR_get_error();
					const char* error_str = ERR_error_string(error, NULL);
					printf("could not SSL_read(returned 0): %s\n", error_str);
					goto tryAgain;
				}
				else if (bytes == 0)
				{
					printf("Client closed connection\n");
					s->_terminate = true;
					break;
				}
				else
					s->_readCallBack(s, data, bytes);
			}
		}
	}
	s->_threadRunning = false;

	return NULL;
}

SSLClient::~SSLClient()
{
	if (_threadRunning)
	{
		void *ret;
		
		_threadRunning = false;

		_terminate = true;
		pthread_join(_thread, &ret);
	}
	if (_client_ctx)
	{
		SSL_set_shutdown(_client_ctx, SSL_SENT_SHUTDOWN|SSL_RECEIVED_SHUTDOWN);
		SSL_shutdown(_client_ctx);
		SSL_free(_client_ctx);
	}
	if (_ctx)
		SSL_CTX_free(_ctx);
	if (_socket != -1)
		close(_socket);
	pthread_mutex_destroy(&_mutex);
	pthread_cond_destroy(&_cond);
	pthread_mutex_destroy(&_timeoutMutex);
	pthread_cond_destroy(&_timeoutCond);
}

SSLClient::SSLClient(std::string &ip, int port, const SSL_METHOD *method, std::string &sslCertFile, std::string &sslKeyFile, std::string &caCertFile, SSLSocketMode mode, bool ownThread)
{
	_ip = ip;
	_port = port;
	_ctx = NULL;
	_client_ctx = NULL;
	_threadRunning = false;
	_terminate = false;
	_method = method;
	_mode = mode;
	_socket = -1;
	_ownThread = ownThread;
	_userData = this;
	_udpSbio = NULL;
	_timeout = 0;

	if (sslCertFile.length() && sslKeyFile.length())
	{
		_sslCert.LoadCert(sslCertFile, FORMAT_PEM);
		_sslCert.LoadKey(sslKeyFile, FORMAT_PEM);
	}
	_caCertFile = caCertFile;

	pthread_mutex_init(&_mutex, NULL);
    pthread_cond_init(&_cond, NULL);
	pthread_mutex_init(&_timeoutMutex, NULL);
    pthread_cond_init(&_timeoutCond, NULL);
}

SSLClient::SSLClient(int sock, const SSL_METHOD *method, std::string &sslCertFile, std::string &sslKeyFile, std::string &caCertFile, SSLSocketMode mode, bool ownThread)
{
	_ip = "";
	_port = -1;
	_ctx = NULL;
	_client_ctx = NULL;
	_threadRunning = false;
	_terminate = false;
	_method = method;
	_mode = mode;
	_socket = sock;
	_ownThread = ownThread;
	_userData = this;
	_udpSbio = NULL;
	_timeout = 0;

	if (sslCertFile.length() && sslKeyFile.length())
	{
		_sslCert.LoadCert(sslCertFile, FORMAT_PEM);
		_sslCert.LoadKey(sslKeyFile, FORMAT_PEM);
	}
	_caCertFile = caCertFile;

	pthread_mutex_init(&_mutex, NULL);
    pthread_cond_init(&_cond, NULL);
	pthread_mutex_init(&_timeoutMutex, NULL);
    pthread_cond_init(&_timeoutCond, NULL);
}

bool SSLClient::SocketConnect()
{
	struct sockaddr_in sin;

	if (_mode == SOCKET_MODE_TCP)
		_socket = socket(AF_INET, SOCK_STREAM, 0);
	else if (_mode == SOCKET_MODE_UDP)
		_socket = socket(AF_INET, SOCK_DGRAM, 0);
	else
		_socket = -1;

	if (_socket < 0)
    {
		printf("\n Error : Could not create socket \n");
		return false;
    } 

	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_port = htons((short)_port);
	sin.sin_addr.s_addr = inet_addr(_ip.c_str());

	if (connect(_socket, (struct sockaddr *)&sin, sizeof(sin)) < 0)
    {
       printf("\n Error : Connect Failed \n");
       return false;
    } 

	return true;
}

void SSLClient::InitContext()
{
	_ctx = SSL_CTX_new(_method);

	SSL_CTX_set_verify(_ctx, SSL_VERIFY_PEER, SSLServer::VerifyCallback);

	if (_sslCert.CanVerify())
		SSL_CTX_use_certificate(_ctx, _sslCert.UseCertificate());

	if (_sslCert.CanSign())
		SSL_CTX_use_PrivateKey(_ctx, _sslCert.UsePrivateKey());

	if (_caCertFile.length())
	{
		if (!SSL_CTX_load_verify_locations(_ctx, _caCertFile.c_str(), NULL))
			return;
	}

	SSL_CTX_set_client_CA_list(_ctx, SSL_load_client_CA_file(_caCertFile.c_str()));

	if (!SSL_CTX_set_default_verify_paths(_ctx)) 
		return;

	if (_mode == SOCKET_MODE_UDP)
		SSL_CTX_set_read_ahead(_ctx, 1);
}

bool SSLClient::SSLConnect()
{
	InitContext();

	if (_ctx == NULL)
		return false;

	if (_socket == -1)
	{
		if (!SocketConnect())
			return false;
	}

	_client_ctx = SSL_new(_ctx);
	if (_client_ctx ==  NULL)
		return false;

	if (_mode == SOCKET_MODE_UDP)
	{
		struct sockaddr_in peer;
		socklen_t peerlen = sizeof(peer);

		_udpSbio = BIO_new_dgram(_socket, BIO_NOCLOSE);
		if (getsockname(_socket, (struct sockaddr *)&peer, &peerlen) < 0) 
		{
			close(_socket);
			_socket = -1;
			return false;
		}
		std::string from = inet_ntoa(peer.sin_addr);
		printf("Client address=%s\n", from.c_str());

		BIO_ctrl_set_connected(_udpSbio, 1, &peer);
		BIO_ctrl(_udpSbio, BIO_CTRL_DGRAM_MTU_DISCOVER, 0, NULL);
		SSL_set_bio(_client_ctx, _udpSbio, _udpSbio);
		SSL_set_connect_state(_client_ctx);
	}
	else
		SSL_set_fd(_client_ctx, _socket);

	int ret;
	int err;

	ret = SSL_connect(_client_ctx);
	if (ret < 0)
	{
		err = SSL_get_error(_client_ctx, ret);
		printf("Handshake failure %d %s errno=%d\n", err, ERR_error_string(err, NULL), errno);
		return false;
	}
	else if (ret == 0)
	{
		err = SSL_get_error(_client_ctx, ret);
		printf("Handshake Protocol failure %d %s\n", err, ERR_error_string(err, NULL));
		return false;
	}

	printf("Connected with %s encryption\n", SSL_get_cipher(_client_ctx));

	X509 *cert = SSL_get_peer_certificate(_client_ctx);
	if (NULL == cert)
		return false;
	else
	{
		CX509Certificate x;

		x.SetCertificate(cert);
		X509_free(cert); 
		x.Print();
	}

	if (_caCertFile.length())
	{
		long res = SSL_get_verify_result(_client_ctx);
		if (!(X509_V_OK == res)) 
			return false;
	}

	if (!_ownThread)
	{
		_threadRunning = true;
		pthread_create(&_thread, NULL, &SSLClientThread, (void *)this);
	}
	
	return true;
}

void SSLClient::Write(uint8_t *buf, int length)
{
tryAgain:
	_timeout = 0;
	int num = SSL_write(_client_ctx, buf, length);
	if (num > 0)
	{
		if (num == length)
			return;
	}
	else if (num == 0)
	{
		int ssl_error = SSL_get_error(_client_ctx, num);
		if ((ssl_error == SSL_ERROR_WANT_WRITE)||(ssl_error == SSL_ERROR_WANT_READ))
			goto tryAgain;
		long error = ERR_get_error();
		const char* error_str = ERR_error_string(error, NULL);
		printf("could not SSL_write (returned 0): %s\n", error_str);
		goto tryAgain;
	}
	else if (num < 0)
	{
		int ssl_error = SSL_get_error(_client_ctx, num);
		if ((ssl_error == SSL_ERROR_WANT_WRITE)||(ssl_error == SSL_ERROR_WANT_READ))
			goto tryAgain;
		long error = ERR_get_error();
		const char* error_str = ERR_error_string(error, NULL);
		printf("could not SSL_write (returned 0): %s\n", error_str);
		goto tryAgain;
	}
}

bool SSLClient::ThreadRunning()
{
	return _threadRunning;
}

void SSLClient::ReadCallBack(void (*readCallBack)(void *ud, uint8_t *, int))
{
	_readCallBack = readCallBack;
}

void SSLClient::SetUserData(void *ud)
{
	_userData = ud;
}

void SSLClient::Lock()
{
	pthread_mutex_lock(&_mutex);
}

void SSLClient::Wait()
{
	pthread_cond_wait(&_cond, &_mutex);
}

void SSLClient::Signal()
{
	pthread_cond_signal(&_cond);
}

void SSLClient::Unlock()
{
	pthread_mutex_unlock(&_mutex);
}

void SSLClient::LockTimeout()
{
	pthread_mutex_lock(&_timeoutMutex);
}

void SSLClient::WaitTimeout()
{
	pthread_cond_wait(&_timeoutCond, &_timeoutMutex);
}

void SSLClient::SignalTimeout()
{
	pthread_cond_signal(&_timeoutCond);
}

void SSLClient::UnlockTimeout()
{
	pthread_mutex_unlock(&_timeoutMutex);
}
