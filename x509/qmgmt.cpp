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
#include <event2/buffer.h>
#include <event2/bufferevent_ssl.h>

#include <x509.hpp>
#include <ca.hpp>
#include <ini.h>

#include "qmgmt.hpp"

using namespace std;

std::vector<WaitingPayload *> waitingPayloads;
pthread_mutex_t WaitingPayload::_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t WaitingPayload::_cond = PTHREAD_COND_INITIALIZER;

std::vector<WorkerThread *> threadPool;

void WaitingPayload::WaitingPayloadInit()
{
	pthread_mutex_init(&_mutex, NULL);
	pthread_cond_init(&_cond, NULL);
}

void WaitingPayload::AddToWaitingJobs(WaitingPayload *wp)
{
	pthread_mutex_lock(&_mutex);
	waitingPayloads.push_back(wp);
	pthread_cond_signal(&_cond);
	pthread_mutex_unlock(&_mutex);
}

WaitingPayload::~WaitingPayload()
{
	if (_data)
		delete _data;
}

WaitingPayload::WaitingPayload(struct evbuffer *in, SSL *s, struct bufferevent *bev, void *ud, void (*job)(WaitingPayload *wp, void *ud))
{
	_job = job;
	_session = s;
	_bev = bev;
	_userData = ud;
	_data = NULL;
	_length = (int)evbuffer_get_length(in);
	if (_length < sizeof(int))
		return;
	_data = new uint8_t[_length];
	if (_data)
		evbuffer_remove(in, _data, _length);
}

void WaitingPayload::Job()
{
	if (_job)
		this->_job(this, _userData);
}

static void *WorkerFunction(void *ptr) 
{
	WorkerThread *worker = (WorkerThread *)ptr;

	while (1) 
	{
		pthread_mutex_lock(&WaitingPayload::_mutex);
		while (waitingPayloads.size() == 0)
		{
			if (worker->_terminate)
				break;

			pthread_cond_wait(&WaitingPayload::_cond, &WaitingPayload::_mutex);
		}

		if (worker->_terminate)
		{
			pthread_mutex_unlock(&WaitingPayload::_mutex);
			break;
		}

		WaitingPayload *wp = waitingPayloads[0];
		if (wp)
			waitingPayloads.erase(waitingPayloads.begin());
		pthread_mutex_unlock(&WaitingPayload::_mutex);

		if (wp == NULL)
			continue;

		wp->Job();
		delete wp;
	}

	printf("Worker thread exitted\n");

	pthread_exit(NULL);
}

WorkerThread::~WorkerThread() 
{
	void *ret;

	_terminate = 1;
	pthread_join(_thread, &ret); 
}

WorkerThread::WorkerThread()
{
	_terminate = 0;
	if (pthread_create(&_thread, NULL, WorkerFunction, (void *)this))
	{
		perror("Failed to start all worker threads");
		return;
	}
}

void WorkerThread::Init(int poolSz)
{
	for (int i = 0; i < poolSz; i++)
		threadPool.push_back(new WorkerThread());
}
