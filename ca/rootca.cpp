#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <pthread.h>
#include <signal.h>
#include <openssl/ssl.h>
#include <openssl/crypto.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/rand.h>

#include <event.h>
#include <event2/listener.h>
#include <event2/bufferevent_ssl.h>

#include <x509.hpp>
#include <qmgmt.hpp>
#include <ca.hpp>
#include <ini.h>
#include <stream.h>

#include "policy.h"

pthread_mutex_t * ssl_locks;
int ssl_num_locks;

using namespace std;

#define MATCH(s, n) strcasecmp(section, s) == 0 && strcasecmp(name, n) == 0

CaPolicy caPolicy;
CertPolicy certPolicy;
SSLCertPolicy sslCertPolicy;
GatewayPolicy gatewayPolicy;

CCA *cca;
CCA *deviceCa;

struct event_base *eventBase;

void sigterm_action(int fd, short event, void *bula)
{
	event_base_loopbreak(eventBase);
}

static int getDaemonSection(void *user, const char *section, const char *name, const char *value)
{
	if (MATCH("DAEMON", "port"))
		sscanf(value, "%d", &caPolicy.port);
	else if (MATCH("DAEMON", "portAuth"))
		sscanf(value, "%d", &caPolicy.portAuth);

	return 1;
}

static int getCaPolicy(void *user, const char *section, const char *name, const char *value)
{
	if (MATCH("POLICY_CA_CERT", "keyStrength"))
		caPolicy.keyStrength = value;
	else if (MATCH("POLICY_CA_CERT", "period"))
		caPolicy.period = value;
	else if (MATCH("POLICY_CA_CERT", "renew"))
		sscanf(value, "%d", &caPolicy.renew);
	else if (MATCH("POLICY_CA_CERT", "country"))
		caPolicy.country = value;
	else if (MATCH("POLICY_CA_CERT", "serialFile"))
		caPolicy.serialFile = value;
	else if (MATCH("POLICY_CA_CERT", "caCertFile"))
		caPolicy.caCertFile = value;
	else if (MATCH("POLICY_CA_CERT", "caKeyFile"))
		caPolicy.caKeyFile = value;
	else if (MATCH("POLICY_CA_CERT", "subjectName"))
		caPolicy.subjectName = value;
	else if (MATCH("POLICY_CA_CERT", "companyName"))
		caPolicy.companyName = value;

	return 1;
}

static int getGatewayPolicy(void *user, const char *section, const char *name, const char *value)
{
	if (MATCH("POLICY_GATEWAY", "keyStrength"))
		gatewayPolicy.keyStrength = value;
	else if (MATCH("POLICY_GATEWAY", "period"))
		gatewayPolicy.period = value;
	else if (MATCH("POLICY_GATEWAY", "renew"))
		sscanf(value, "%d", &gatewayPolicy.renew);
	else if (MATCH("POLICY_GATEWAY", "country"))
		gatewayPolicy.country = value;
	else if (MATCH("POLICY_CA_CERT", "serialFile"))
		gatewayPolicy.serialFile = value;
	else if (MATCH("POLICY_GATEWAY", "certFile"))
		gatewayPolicy.certFile = value;
	else if (MATCH("POLICY_GATEWAY", "keyFile"))
		gatewayPolicy.keyFile = value;
	else if (MATCH("POLICY_GATEWAY", "subjectName"))
		gatewayPolicy.subjectName = value;
	else if (MATCH("POLICY_GATEWAY", "companyName"))
		gatewayPolicy.companyName = value;

	return 1;
}

static int getCertPolicy(void *user, const char *section, const char *name, const char *value)
{
	if (MATCH("POLICY_CERT", "keyStrength"))
		certPolicy.keyStrength = value;
	else if (MATCH("POLICY_CERT", "period"))
		certPolicy.period = value;
	else if (MATCH("POLICY_CERT", "renew"))
		sscanf(value, "%d", &certPolicy.renew);
	else if (MATCH("POLICY_CERT", "country"))
		certPolicy.country = value;
	else if (MATCH("POLICY_CERT", "companyName"))
		certPolicy.companyName = value;
	else if (MATCH("POLICY_CERT", "gatewayName"))
		certPolicy.gatewayName = value;

	return 1;
}

static int getSSLCertPolicy(void *user, const char *section, const char *name, const char *value)
{
	if (MATCH("POLICY_SSL_CERT", "keyStrength"))
		sslCertPolicy.keyStrength = value;
	else if (MATCH("POLICY_SSL_CERT", "period"))
		sslCertPolicy.period = value;
	else if (MATCH("POLICY_SSL_CERT", "renew"))
		sscanf(value, "%d", &sslCertPolicy.renew);
	else if (MATCH("POLICY_SSL_CERT", "country"))
		sslCertPolicy.country = value;
	else if (MATCH("POLICY_SSL_CERT", "sslCertFile"))
		sslCertPolicy.sslCertFile = value;
	else if (MATCH("POLICY_SSL_CERT", "sslKeyFile"))
		sslCertPolicy.sslKeyFile = value;
	else if (MATCH("POLICY_SSL_CERT", "subjectName"))
		sslCertPolicy.subjectName = value;
	else if (MATCH("POLICY_SSL_CERT", "companyName"))
		sslCertPolicy.companyName = value;

	return 1;
}

void ReadConfiguration()
{
	if (ini_parse("/etc/ca/ca.conf", getDaemonSection, NULL) < 0)
		return;

	if (ini_parse("/etc/ca/ca.conf", getCaPolicy, NULL) < 0)
		return;

	if (ini_parse("/etc/ca/ca.conf", getCertPolicy, NULL) < 0)
		return;

	if (ini_parse("/etc/ca/ca.conf", getSSLCertPolicy, NULL) < 0)
		return;

	if (ini_parse("/etc/ca/ca.conf", getGatewayPolicy, NULL) < 0)
		return;
}

bool GenerateCACertificate(bool *isNew)
{
	*isNew = false;
	bool rv = false;

	std::vector <std::string> args;

	cca = new CCA(caPolicy.serialFile);
	if (!cca->IsValid())
	{
		args.push_back(caPolicy.keyStrength);
		args.push_back(caPolicy.subjectName);
		args.push_back(caPolicy.companyName);
		args.push_back(caPolicy.country);
		args.push_back(caPolicy.period);
		args.push_back(caPolicy.caCertFile);
		args.push_back(caPolicy.caKeyFile);

		rv = cca->GenerateCACert(args);
		if (rv)
			*isNew = true;
	}
	else
	{
		std::string pass = "";
		rv = cca->LoadCACert(caPolicy.caCertFile, caPolicy.caKeyFile, pass);
	}

	return rv;
}

void GenerateSSLCertificate(bool isNew)
{
	struct stat sts;

	bool exists = (stat(sslCertPolicy.sslCertFile.c_str(), &sts) == 0) && (stat(sslCertPolicy.sslKeyFile.c_str(), &sts) == 0);
	if (isNew || !exists)
	{
		std::vector <std::string> args;
		std::string buf;

		args.push_back(sslCertPolicy.keyStrength);
		args.push_back(sslCertPolicy.subjectName);
		args.push_back(sslCertPolicy.companyName);
		args.push_back(sslCertPolicy.country);
		args.push_back(sslCertPolicy.period);
		args.push_back(sslCertPolicy.sslCertFile);
		args.push_back(sslCertPolicy.sslKeyFile);

		CX509Request *req = new CX509Request(args);
		req->SavePrivateKey(sslCertPolicy.sslKeyFile, FORMAT_PEM);
		req->SaveRequestToMemory(buf, FORMAT_PEM);
		delete req;

		req = new CX509Request();
		req->LoadRequestInMemory(buf, FORMAT_PEM);
		CX509Certificate *x = cca->GenerateCertificate(*req, atoi(sslCertPolicy.period.c_str()));
		x->LoadKey(sslCertPolicy.sslKeyFile, FORMAT_PEM);
		x->SaveCertificate(sslCertPolicy.sslCertFile, FORMAT_PEM);

		delete req;
		delete x;

		args.clear();

		system("/etc/init.d/uhttpd restart");
	}
}

void GenerateGatewayCertificate(bool isNew)
{
	struct stat sts;

	bool exists = (stat(gatewayPolicy.certFile.c_str(), &sts) == 0) && (stat(gatewayPolicy.keyFile.c_str(), &sts) == 0);
	if (isNew || !exists)
	{
		std::vector <std::string> args;
		std::string buf;

		args.push_back(gatewayPolicy.keyStrength);
		args.push_back(gatewayPolicy.subjectName);
		args.push_back(gatewayPolicy.companyName);
		args.push_back(gatewayPolicy.country);
		args.push_back(gatewayPolicy.period);
		args.push_back(gatewayPolicy.certFile);
		args.push_back(gatewayPolicy.keyFile);

		CX509Request *req = new CX509Request(args);
		req->SavePrivateKey(gatewayPolicy.keyFile, FORMAT_PEM);
		req->SaveRequestToMemory(buf, FORMAT_PEM);
		delete req;

		req = new CX509Request();
		req->LoadRequestInMemory(buf, FORMAT_PEM);
		CX509Certificate *x = cca->GenerateCertificate(*req, atoi(gatewayPolicy.period.c_str()));
		x->LoadKey(gatewayPolicy.keyFile, FORMAT_PEM);
		x->SaveCertificate(gatewayPolicy.certFile, FORMAT_PEM);

		delete req;
		delete x;

		args.clear();
	}

	deviceCa = new CCA(gatewayPolicy.serialFile);
	if (deviceCa->IsValid())
	{
		std::string pass = "";
		deviceCa->LoadCACert(gatewayPolicy.certFile, gatewayPolicy.keyFile, pass);
	}
}

static bool ResponseToWrite(WaitingPayload *wp, void *ud, MyByteStream &response)
{
	bool rv = false;
	int len;

	len = response.Length();
	uint8_t *tbuf = new uint8_t[len];
	if (tbuf)
	{
		response.Export(tbuf, len);
		SSLServer *sslServer = (SSLServer *)ud;
		rv = sslServer->WriteBufferSSL(wp->_session, tbuf, len);
		delete tbuf;
	}

	return rv;
}

static void ResponseFunctionUdp(void *ud, uint8_t *data, int len)
{
	static int times;
	SSLServer *s = (SSLServer *)ud;
	++times;
	printf("%d. Attempting to write\n", times);
	s->WriteBufferSSL(data, len);
	printf("%d. Done writing\n", times);
}

static void ResponseFunctionAuth(WaitingPayload *wp, void *ud)
{
	if (!wp->_length)
		return;

	std::vector<StreamBuf> dataStream;
	MyByteStream response;
	MyByteStream inBytes(wp->_data, wp->_length);
	inBytes.Get(dataStream);
	if (!dataStream.size())
	{	
		SSLServer *sslServer = (SSLServer *)ud;
		sslServer->WriteBufferSSL(wp->_session, wp->_data, wp->_length);
		return;
	}

	int commandCode = dataStream[0].theData;

	switch (commandCode)
	{
		case ROOT_CERT:
			{
				CX509Certificate *rc = cca->Certificate();
				std::string rcb;				

				printf("Received ROOT_CERT request\n");
				rc->SaveCertToMemory(rcb, FORMAT_PEM);
				response.String2Stream(rcb);

				if (ResponseToWrite(wp, ud, response))
					printf("Root Cert Write Succeeded\n");
				else
					printf("Root Cert Write Failed\n");
			}
			break;

		case CERTIFICATE_CHAIN:
			{
				CX509Certificate *dc = deviceCa->Certificate();
				CX509Certificate *rc = cca->Certificate();
				std::string dcb;				
				std::string rcb;				

				printf("Received CERTIFICATE_CHAIN request\n");

				dc->SaveCertToMemory(dcb, FORMAT_PEM);
				rc->SaveCertToMemory(rcb, FORMAT_PEM);
				
				response.String2Stream(dcb);
				response.String2Stream(rcb);
	
				if (ResponseToWrite(wp, ud, response))
					printf("Chain Write Succeeded\n");
				else
					printf("Chain Write Failed\n");
			}
			break;

		case CERTIFICATE_CHAIN_SSL:
			{
				CX509Certificate sc(sslCertPolicy.sslCertFile, FORMAT_PEM);
				CX509Certificate *rc = cca->Certificate();
				std::string scb;				
				std::string rcb;				

				printf("Received CERTIFICATE_CHAIN_SSL request\n");

				sc.SaveCertToMemory(scb, FORMAT_PEM);
				rc->SaveCertToMemory(rcb, FORMAT_PEM);

				response.String2Stream(scb);
				response.String2Stream(rcb);

				if (ResponseToWrite(wp, ud, response))
					printf("Chain SSL Write Succeeded\n");
				else
					printf("Chain SSL Write Failed\n");
			}
			break;

		case OCSP_REQUEST:
			break;

		default:
			{
				SSLServer *sslServer = (SSLServer *)ud;
				sslServer->WriteBufferSSL(wp->_session, wp->_data, wp->_length);
			}
			break;
	}
}

static void ResponseFunction(WaitingPayload *wp, void *ud)
{
	if (!wp->_length)
		return;

	std::vector<StreamBuf> dataStream;
	MyByteStream response;
	MyByteStream inBytes(wp->_data, wp->_length);
	inBytes.Get(dataStream);
	if (!dataStream.size())
		return;

	int commandCode = dataStream[0].theData;

	switch (commandCode)
	{
		case ROOT_CERT:
			{
				CX509Certificate *rc = cca->Certificate();
				std::string rcb;				

				printf("Received ROOT_CERT request\n");
				rc->SaveCertToMemory(rcb, FORMAT_PEM);
				response.String2Stream(rcb);

				if (ResponseToWrite(wp, ud, response))
					printf("Root Cert Write Succeeded\n");
				else
					printf("Root Cert Write Failed\n");
			}
			break;

		case CERTIFICATE_CHAIN:
			{
				CX509Certificate *dc = deviceCa->Certificate();
				CX509Certificate *rc = cca->Certificate();
				std::string dcb;				
				std::string rcb;				

				printf("Received CERTIFICATE_CHAIN request\n");

				dc->SaveCertToMemory(dcb, FORMAT_PEM);
				rc->SaveCertToMemory(rcb, FORMAT_PEM);
				
				response.String2Stream(dcb);
				response.String2Stream(rcb);
	
				if (ResponseToWrite(wp, ud, response))
					printf("Chain Write Succeeded\n");
				else
					printf("Chain Write Failed\n");
			}
			break;

		case CERTIFICATE_CHAIN_SSL:
			{
				CX509Certificate sc(sslCertPolicy.sslCertFile, FORMAT_PEM);
				CX509Certificate *rc = cca->Certificate();
				std::string scb;				
				std::string rcb;				

				printf("Received CERTIFICATE_CHAIN_SSL request\n");

				sc.SaveCertToMemory(scb, FORMAT_PEM);
				rc->SaveCertToMemory(rcb, FORMAT_PEM);

				response.String2Stream(scb);
				response.String2Stream(rcb);

				if (ResponseToWrite(wp, ud, response))
					printf("Chain SSL Write Succeeded\n");
				else
					printf("Chain SSL Write Failed\n");
			}
			break;

		case CERTIFICATE_REQUEST:
			{
				char rbuff[8192];
				int responseLen;

				printf("Received CERTIFICATE_REQUEST policy request\n");

				memset(rbuff, 0, sizeof(rbuff));
				snprintf(rbuff, sizeof(rbuff), "[POLICY_CERT]\nkeyStrength=%s\ncountry=%s\ncompanyName=%s\ngatewayName=%s\n", certPolicy.keyStrength.c_str(), certPolicy.country.c_str(), 
					certPolicy.companyName.c_str(), certPolicy.gatewayName.c_str());

				response.CString2Stream(rbuff);

				if (ResponseToWrite(wp, ud, response))
					printf("Cert Request Write Succeeded\n");
				else
					printf("Cert Request Write Failed\n");
			}
			break;

		case CERTIFICATE_GENERATE:
			{
				printf("Received CERTIFICATE_GENERATE request\n");
				if (dataStream.size() != 2)
				{
					printf("Certificate Request not found\n"); 
					break;
				}

				CX509Request xreq;

				xreq.LoadRequestInMemory(dataStream[1].stringData, FORMAT_PEM);
	
				CX509Certificate *cert = deviceCa->GenerateCertificate(xreq, atoi(certPolicy.period.c_str()));

				if (cert)
				{
					std::string cb;
					cert->SaveCertToMemory(cb, FORMAT_PEM);

					response.String2Stream(cb);

					if (ResponseToWrite(wp, ud, response))
						printf("Cert Generate Write Succeeded\n");
					else
						printf("Cert Generate Write Failed\n");

					delete cert;
				}
			}
			break;
	}
}

static void *SSLUdpServerControl(void *arg)
{
	SSLServer **sslServer = (SSLServer **)arg;
	SSLServer *s = *sslServer;

	s->Lock();
	s->Wait();
	s->Unlock();

	printf("Caught timeout signal\n");

	delete s;
	*sslServer = NULL;

	return NULL;
}

int main(int argc, char **argv)
{
	daemon(1, 0);

	bool isNew;

	eventBase = event_base_new();
    struct event *term_events[6];
	int theSignals[6] = {SIGTERM, SIGINT, SIGQUIT, SIGHUP, SIGUSR1, SIGUSR2};
	for (int i = 0; i < 6; i++)
	{
		term_events[i] = evsignal_new(eventBase, theSignals[i], sigterm_action, NULL);
		event_add(term_events[i], NULL);
	}

	SSLServer::Init();

	ReadConfiguration();
	if (GenerateCACertificate(&isNew))
	{
		GenerateSSLCertificate(isNew);
		GenerateGatewayCertificate(isNew);

		SSLServer *sslServer = new SSLServer(caPolicy.port, TLSv1_2_server_method(), sslCertPolicy.sslCertFile, sslCertPolicy.sslKeyFile, caPolicy.caCertFile);
		sslServer->SetUserData(sslServer);
		sslServer->SetResponseCallback(ResponseFunction);

		SSLServer *sslServerAuth = new SSLServer(caPolicy.portAuth, TLSv1_2_server_method(), gatewayPolicy.certFile, gatewayPolicy.keyFile, caPolicy.caCertFile, true, true, 2);
		sslServerAuth->SetUserData(sslServerAuth);
		sslServerAuth->SetResponseCallback(ResponseFunctionAuth);

#if 0
		MessagingServer *messagingServer = new MessagingServer();

		sslServerAuth->SetSessionStartCallback(SessionStartCallback);
		sslServerAuth->SetSessionEndCallback(SessionEndCallback);

		SSLServer *sslServerUdp = new SSLServer(DTLSv1_2_server_method(), gatewayPolicy.certFile, gatewayPolicy.keyFile, caPolicy.caCertFile, true, true, 2, SOCKET_MODE_UDP);
		sslServerUdp->SetUserData(sslServerUdp);
		sslServerUdp->SetUDPResponseCallback(ResponseFunctionUdp);

		struct sockaddr_in sin;

		memset(&sin, 0, sizeof(sin));
		sin.sin_family = AF_INET;
		sin.sin_port = htons((short)5000);
		sin.sin_addr.s_addr = INADDR_ANY;

		int udpSocket = socket(AF_INET, SOCK_DGRAM, 0);
		bind(udpSocket, (struct sockaddr *)&sin, sizeof (sin));

		int j = 1;

		evutil_make_socket_nonblocking(udpSocket);
		setsockopt(udpSocket, SOL_SOCKET, SO_REUSEADDR, (void *)&j, sizeof(j));
#endif
		if (sslServer->Run() && sslServerAuth->Run() /*&& sslServerUdp->Run(udpSocket) && messagingServer->Run()*/)
		{
//			pthread_t thread;

//			pthread_create(&thread, NULL, SSLUdpServerControl, (void *)(void **)&sslServerUdp);
    		event_base_dispatch(eventBase);
			delete sslServer;
			delete sslServerAuth;
//			if (sslServerUdp)
//				delete sslServerUdp;
//			delete messagingServer;
		}
	}

	if (cca)
		delete cca;

	if (deviceCa)
		delete deviceCa;
	
	if (eventBase)
		event_base_free(eventBase);

	return 0;
}
