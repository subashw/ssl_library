#include <map>
#include <list>
#include <string>
#include <vector>

class nicCache
{
public:
    char m_nic[32];
    char m_mac[13];
    char m_ipv4[16];
    bool m_hasMac;
    bool m_hasIp;
    bool m_loopback;
    char m_gatewayIp[16];
    char m_gatewayMac[13];
    nicCache();
    nicCache(const nicCache &);
	void operator=(const nicCache &);
    virtual ~nicCache();
};

void GetNetworkConfig(std::vector <nicCache> &myInterfaces);
void FreeInteraces(std::vector <nicCache> &myInterfaces);
int ServerMulticastSocket(char *interface, char *multicastAddr, short multicastPort, char *myIpV4, int recvBuffSz);
int ClientMulticastSocket(struct sockaddr_in *mcastSockAddress, char *interface, char *multicastAddr, int multicastPort, char *myIpV4, int sndBuffSz);
void ClientMulticastSocketClose(int fd, char *interface, char *multicastAddr, int multicastPort, char *myIpV4);

