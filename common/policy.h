#include <cstdlib>
#include <string>
#include <vector>

using namespace std;

struct CaPolicy
{
	int port;
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
	std::string certFile;
	std::string keyFile;
	std::string subjectName;
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

#define CONFIG_DIRECTORY "/etc/RemoteClinic"
#define DEVICE_CERT_FILE "/etc/RemoteClinic/deviceCert.pem"
#define DEVICE_KEY_FILE "/etc/RemoteClinic/deviceCertKey.pem"
#define USER_CERT_FILE "userCert.pem"
#define USER_KEY_FILE "userCertKey.pem"
#define INSTRUMENTS_CONF_FILE "/etc/RemoteClinic/instruments.conf"
#define INSTRUMENTS_CONF_FILE_USER "instruments.conf"
#define INSTRUMENTS_CONF_FILE_USER_RECEIVER "instrumentsReceiver.conf"
#define CERT_POLICY_FILE "certPolicy.conf"
