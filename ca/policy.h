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

#include <event.h>
#include <event2/listener.h>
#include <event2/bufferevent_ssl.h>

#include <x509.hpp>
#include <ca.hpp>
#include <ini.h>

using namespace std;

struct CaPolicy
{
	int port;
	int portAuth;
	std::string keyStrength;
	std::string period;
	int renew;
	std::string country;
	std::string subjectName;
	std::string serialFile;
	std::string caCertFile;
	std::string caKeyFile;
	std::string companyName;
};

struct GatewayPolicy
{
	std::string keyStrength;
	std::string period;
	int renew;
	std::string country;
	std::string subjectName;
	std::string serialFile;
	std::string certFile;
	std::string keyFile;
	std::string companyName;
};

struct SSLCertPolicy
{
	std::string keyStrength;
	std::string period;
	int renew;
	std::string country;
	std::string subjectName;
	std::string sslCertFile;
	std::string sslKeyFile;
	std::string companyName;
};

struct CertPolicy
{
	std::string keyStrength;
	std::string period;
	int renew;
	std::string country;
	std::string companyName;
	std::string gatewayName;
};

enum COMMAND_CODES 
{
	ROOT_CERT=0,
	CERTIFICATE_CHAIN,
	CERTIFICATE_CHAIN_SSL,
	CERTIFICATE_REQUEST,
	CERTIFICATE_GENERATE,
	OCSP_REQUEST
};

struct CommandStructure
{
	int opCode;
	int len;
	char *payload;
};
