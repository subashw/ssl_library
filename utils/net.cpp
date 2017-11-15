#include <map>
#include <list>
#include <string>
#include <vector>

using namespace std;

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <err.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <fcntl.h>
#include <ctype.h>
#include <errno.h>
#include <unistd.h>

#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#ifdef __linux__
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#endif

#include <ifaddrs.h>
#include <syslog.h>

#include "net.h"

#ifdef __linux__
#define AF_LINK AF_PACKET
#else
#include <net/if_dl.h>
#define LLADDR(s) ((caddr_t)((s)->sdl_data + (s)->sdl_nlen))
#endif

nicCache::~nicCache()
{
}

nicCache::nicCache()
{
	memset(m_nic, 0, sizeof(m_nic));
	memset(m_mac, 0, sizeof(m_mac));
	memset(m_ipv4, 0, sizeof(m_ipv4));
	memset(m_gatewayIp, 0, sizeof(m_gatewayIp));
	memset(m_gatewayMac, 0, sizeof(m_gatewayMac));
	m_hasMac = false;
	m_hasIp = false;
	m_loopback = false;
}

nicCache::nicCache(const nicCache &n)
{
	strcpy(m_nic, n.m_nic);
	strcpy(m_mac, n.m_mac);
	strcpy(m_ipv4, n.m_ipv4);
	strcpy(m_gatewayIp, n.m_gatewayIp);
	strcpy(m_gatewayMac, n.m_gatewayMac);
	m_hasMac = n.m_hasMac;
	m_hasIp = n.m_hasIp;
	m_loopback = n.m_loopback;
}

void nicCache::operator=(const nicCache &n)
{
	strcpy(m_nic, n.m_nic);
	strcpy(m_mac, n.m_mac);
	strcpy(m_ipv4, n.m_ipv4);
	strcpy(m_gatewayIp, n.m_gatewayIp);
	strcpy(m_gatewayMac, n.m_gatewayMac);
	m_hasMac = n.m_hasMac;
	m_hasIp = n.m_hasIp;
	m_loopback = n.m_loopback;
}

void GetNetworkConfig(std::vector <nicCache> &myInterfaces)
{
    struct ifaddrs *ifAddrStruct=NULL;
    struct ifaddrs *ifa=NULL;
    void *tmpAddrPtr=NULL;
    unsigned char *ptr;
	bool getIp;
	bool getMac;
	bool found;
	bool loopback;

    getifaddrs(&ifAddrStruct);
 
    for (ifa = ifAddrStruct; ifa != NULL; ifa = ifa->ifa_next)
    {
		if (ifa->ifa_addr == NULL)
        	continue;

		getMac = false;
		getIp = false;
		loopback = false;

		if (ifa->ifa_addr->sa_family == AF_LINK)
		{
			if (ifa->ifa_flags&IFF_UP)
			{
				if (ifa->ifa_flags&IFF_MULTICAST)
				{
					if (ifa->ifa_flags&IFF_RUNNING)
					{
						if (ifa->ifa_flags&IFF_LOOPBACK)
							loopback = true;
						else
							getMac = true;
					}
				}
				else
				{
					if (ifa->ifa_flags&IFF_RUNNING)
					{
						if (ifa->ifa_flags&IFF_LOOPBACK)
							loopback = true;
						else
							getMac = true;
					}
				}
			}
		}
		else if (ifa->ifa_addr->sa_family == AF_INET)
		{
			if (ifa->ifa_flags&IFF_UP)
			{
				if (ifa->ifa_flags&IFF_MULTICAST)
				{
					if (ifa->ifa_flags&IFF_RUNNING)
					{
						getIp = true;
						loopback = ifa->ifa_flags&IFF_LOOPBACK;
					}
				}
				else
				{
					if (ifa->ifa_flags&IFF_RUNNING)
					{
						getIp = true;
						loopback = ifa->ifa_flags&IFF_LOOPBACK;
					}
				}
			}
		}
		else
			continue;

		nicCache iface;
		found = false;
		int foundIndex = -1;

		for (int i = 0; i < (int)myInterfaces.size(); i++)
		{
			if (!strcmp(myInterfaces[i].m_nic, ifa->ifa_name))
 			{
				foundIndex = i;
				found = true;
				break;
			}
		}

		if (!found)
		{
			strncpy(iface.m_nic, ifa->ifa_name, sizeof(iface.m_nic));
			myInterfaces.push_back(iface);
			foundIndex = (int)myInterfaces.size()-1;
		}

		if (getIp)
		{
			tmpAddrPtr=&((struct sockaddr_in *)ifa->ifa_addr)->sin_addr;
			inet_ntop(AF_INET, tmpAddrPtr, myInterfaces[foundIndex].m_ipv4, INET_ADDRSTRLEN);
			myInterfaces[foundIndex].m_hasIp = true;
			myInterfaces[foundIndex].m_loopback = loopback;
		}

		if (getMac)
		{
#ifdef __linux__
			struct ifreq ifr;
			int fd = socket(AF_INET, SOCK_DGRAM, 0);
			ifr.ifr_addr.sa_family = AF_INET;
			strcpy(ifr.ifr_name, ifa->ifa_name);
			ioctl(fd, SIOCGIFHWADDR, &ifr);
			close(fd);
            
			ptr = (unsigned char *)ifr.ifr_hwaddr.sa_data;
#else
			ptr = (unsigned char *)LLADDR((struct sockaddr_dl *)(ifa)->ifa_addr);
#endif
            snprintf(myInterfaces[foundIndex].m_mac, sizeof(myInterfaces[foundIndex].m_mac), "%02x%02x%02x%02x%02x%02x",
				*ptr, *(ptr+1), *(ptr+2), *(ptr+3), *(ptr+4), *(ptr+5));
			myInterfaces[foundIndex].m_hasMac = true;	
		}
    }
    
    if (ifAddrStruct!=NULL)
        freeifaddrs(ifAddrStruct);
}

void FreeInteraces(std::vector <nicCache> &myInterfaces)
{
	myInterfaces.clear();
}

static int setnonblock(int fd) 
{
	int flags;

	flags = fcntl(fd, F_GETFL);
	if (flags < 0) 
		return flags;

	flags |= O_NONBLOCK;
	if (fcntl(fd, F_SETFL, flags) < 0) 
		return -1;

	return 0;
}

int if_set_opt(int fd)
{
#ifndef __linux__
	int	 yes = 1;
    
	if (setsockopt(fd, IPPROTO_IP, IP_RECVIF, &yes, sizeof(int)) < 0)
		return (-1);
    
	if (setsockopt(fd, IPPROTO_IP, IP_RECVDSTADDR, &yes, sizeof(int)) < 0)
		return (-1);
#endif
    
	return (0);
}

int if_set_mcast_ttl(int fd, u_int8_t ttl)
{
	if (setsockopt(fd, IPPROTO_IP, IP_MULTICAST_TTL, (char *)&ttl, sizeof(ttl)) < 0)
		return (-1);
    
	return (0);
}

int if_set_mcast_loop(int fd)
{
	u_int8_t	 loop = 0;
    
	if (setsockopt(fd, IPPROTO_IP, IP_MULTICAST_LOOP, (char *)&loop, sizeof(loop)) < 0)
		return (-1);
    
	return (0);
}

void if_set_recvbuf(int fd)
{
	int	 bsize;
    
	bsize = 65536;
	while (setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &bsize, sizeof(bsize)) == -1)
		bsize /= 2;
}

int if_join_group(int fd, char *mcastIp, char *myIp, char *interface)
{
	struct ip_mreqn  mreq;
    struct in_addr   addr;
    struct in_addr   laddr;
    
    inet_aton(mcastIp, &addr);
    inet_aton(myIp, &laddr);
    mreq.imr_multiaddr.s_addr = addr.s_addr;
    mreq.imr_address.s_addr = laddr.s_addr;
    mreq.imr_ifindex = if_nametoindex(interface);
    if (setsockopt(fd, IPPROTO_IP, IP_ADD_MEMBERSHIP, (void *)&mreq, sizeof(mreq)) < 0)  
        return (-1);
    
    return 0;
}

int if_leave_group(int fd, char *mcastIp, char *myIp, char *interface)
{
    struct ip_mreqn  mreq;
    struct in_addr   addr;
    struct in_addr   laddr;

    inet_aton(mcastIp, &addr);
    inet_aton(myIp, &laddr);
    mreq.imr_multiaddr.s_addr = addr.s_addr;
    mreq.imr_address.s_addr = laddr.s_addr;
    mreq.imr_ifindex = if_nametoindex(interface);
    if (setsockopt(fd, IPPROTO_IP, IP_DROP_MEMBERSHIP, (void *)&mreq, sizeof(mreq)) < 0)
        return (-1);

    return 0;
}

int ServerMulticastSocket(char *interface, char *multicastAddr, short multicastPort, char *myIpV4, int recvBuffSz)
{
	struct sockaddr_in addr;
	int sock = -1;
    
	if ((sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) == -1)
		return sock;
 
#ifdef __linux__
	ifreq ifr;
	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, interface, sizeof(ifr.ifr_name));
	if (setsockopt(sock, SOL_SOCKET, SO_BINDTODEVICE, (void *)&ifr, sizeof(ifr)) < 0)
	{
		if (sock != -1)
			close(sock);
		return -1;
	}
#endif

	addr.sin_family = AF_INET;
	addr.sin_port = htons(multicastPort);
	addr.sin_addr.s_addr = INADDR_ANY;
    
	if (::bind(sock, (struct sockaddr *)&addr, sizeof(addr)) == -1)
	{
		if (sock != -1)
			close(sock);
		if (errno == EADDRINUSE)
			return 0;
		else
			return -1;
	}
    
	if (if_set_opt(sock) == -1)
	{
		if (sock != -1)
			close(sock);
		return sock;
	}
    
	if (if_set_mcast_ttl(sock, 255) == -1)
	{
		if (sock != -1)
			close(sock);
		return sock;
	}
    
	if (if_set_mcast_loop(sock) == -1)
	{
		if (sock != -1)
			close(sock);
		return sock;
	}
    
	if_set_recvbuf(sock);
    
    if (if_join_group(sock, multicastAddr, myIpV4, interface) == -1)
	{
		if (sock != -1)
			close(sock);
		return sock;
	}
    
    socklen_t sz = sizeof(recvBuffSz);
    if (getsockopt(sock, SOL_SOCKET, SO_RCVBUF,(void *)&recvBuffSz, &sz) < 0)
        perror((const char *)"Receive buffer size get fail");

	return sock;    
}

int ClientMulticastSocket(struct sockaddr_in *mcastSockAddress, char *interface, char *multicastAddr, int multicastPort, char *myIpV4, int sndBuffSz)
{
	int sock = -1;
    u_char no = 0;
    u_char ttl;

    memset(mcastSockAddress, 0, sizeof(struct sockaddr_in));
    mcastSockAddress->sin_family = AF_INET;
    mcastSockAddress->sin_port = htons(multicastPort);
    mcastSockAddress->sin_addr.s_addr = inet_addr(multicastAddr);

    if ( (sock=socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0)
		return -1;

#ifdef __linux__
    ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, interface, sizeof(ifr.ifr_name));
    if (setsockopt(sock, SOL_SOCKET, SO_BINDTODEVICE, (void *)&ifr, sizeof(ifr)) < 0)
	{
//		if (sock != -1)
//			close(sock);
//		return -1;
	}
#endif

    ttl = 255;
    if (setsockopt(sock, IPPROTO_IP, IP_MULTICAST_TTL, &ttl, sizeof(ttl)) < 0)
	{
		printf("%d\n", errno);
		if (sock != -1)
			close(sock);
		return -1;
	}

    /* Disable Loop-back */
    if (setsockopt(sock, IPPROTO_IP, IP_MULTICAST_LOOP, &no, sizeof(no)) < 0)
	{
		printf("%d\n", errno);
		if (sock != -1)
			close(sock);
		return -1;
	}

    struct in_addr myAddr;
    myAddr.s_addr = inet_addr(myIpV4);

    if (setsockopt(sock, IPPROTO_IP, IP_MULTICAST_IF, &myAddr.s_addr, sizeof(myAddr.s_addr)) < 0)
	{
		printf("%d\n", errno);
		if (sock != -1)
			close(sock);
		return -1;
	}

    socklen_t sz = sizeof(sndBuffSz);
    if (getsockopt(sock, SOL_SOCKET, SO_SNDBUF,(void *)&sndBuffSz, &sz) < 0)
        perror((const char *)"Receive buffer size get fail");

	return sock;
}

void ClientMulticastSocketClose(int fd, char *interface, char *multicastAddr, int multicastPort, char *myIpV4)
{
	if_leave_group(fd, multicastAddr, myIpV4, interface);
	close(fd);
}
