#include "getHostInfo.h"

bool getHostMacAddress(const char *interfaceName, Mac* macAddress)
{
	int sockfd;
	struct ifreq ifr;

	// 소켓 생성
	sockfd = socket(AF_INET, SOCK_DGRAM, 0);
	if (sockfd < 0)
	{
		printf("[ERR] socket error\n");
		return false;
	}

	// 인터페이스 이름 설정
	strncpy(ifr.ifr_name, interfaceName, IFNAMSIZ - 1);
	ifr.ifr_name[IFNAMSIZ - 1] = '\0';

	// MAC 주소 가져오기
	if (ioctl(sockfd, SIOCGIFHWADDR, &ifr) == -1)
	{
		printf("[ERR] ioctl error\n");
		close(sockfd);
		return false;
	}

	// MAC 주소 복사
	// memcpy(macAddress, ifr.ifr_hwaddr.sa_data, 6);
	*macAddress = (uint8_t *)(ifr.ifr_hwaddr.sa_data);

	printf("[+] attackerMac  : %s\n", std::string(*macAddress).c_str());
	close(sockfd);
	return true;
}

bool getHostIpAddress(const char *interfaceName, Ip* ipAddress)
{
	int sockfd;
	struct ifreq ifr;

	// 소켓 생성
	sockfd = socket(AF_INET, SOCK_DGRAM, 0);
	if (sockfd < 0)
	{
		printf("[ERR] socket error\n");
		return false;
	}

	// 인터페이스 이름 설정
	strncpy(ifr.ifr_name, interfaceName, IFNAMSIZ - 1);
	ifr.ifr_name[IFNAMSIZ - 1] = '\0';

	// IP 주소 가져오기
	if (ioctl(sockfd, SIOCGIFADDR, &ifr) == -1)
	{
		printf("[ERR] ioctl error\n");
		close(sockfd);
		return false;
	}

	// IP 주소 복사
	*ipAddress = Ip(inet_ntoa(((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr));
	printf("[+] attackerIp   : %s\n", std::string(*ipAddress).c_str());

	close(sockfd);
	return true;
}

int getHostInfo(const char *interfaceName, Ip *ipAddress, Mac *macAddress)
{	
	printf("\n----------------------------------------\n");
	printf("[*] get host info..");
	printf("\n----------------------------------------\n");
	bool ipOk = getHostIpAddress(interfaceName, ipAddress);
	bool macOk = getHostMacAddress(interfaceName, macAddress);
	if(!ipOk)
		printf("[*] failed to get Host Ip\n");
	if(!macOk)
		printf("[*] failed to get Host Mac\n");
	if(!ipOk || !macOk)
		return -1;
	return 0;
}

