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
#include <netinet/in.h>
#include <arpa/inet.h>

#include <pthread.h>
#include <openssl/ssl.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/rand.h>

#include <event2/event.h>
#include <event2/listener.h>
#include <event2/bufferevent_ssl.h>

using namespace std;

class WaitingPayload
{
	public:
		static pthread_mutex_t _mutex;
		static pthread_cond_t _cond;

	public:
		void (*_job)(WaitingPayload *wp, void *ud);
		struct bufferevent *_bev;
		SSL *_session;
		uint8_t *_data;
		int _length;
		void *_userData;

	public:
		static void WaitingPayloadInit();
		static void AddToWaitingJobs(WaitingPayload *wp);
		virtual ~WaitingPayload();
		WaitingPayload(struct evbuffer *in, SSL *s, struct bufferevent *bev, void *ud, void (*job)(WaitingPayload *wp, void *ud));
		void Job();
};

class WorkerThread
{
	public:
		static void Init(int psz);
		pthread_t _thread;
		int _terminate;

	public:
		virtual ~WorkerThread();
		WorkerThread();
};
