#include <stdio.h>
#include <string>
#include <string.h>
#include <pcap.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "ethhdr.h"
#include "arphdr.h"
#include <unistd.h>
#include <sys/ioctl.h>
#include <net/if.h>

int getHostInfo(const char *, Ip *, Mac *);
bool getHostIpAddress(const char *, Ip *);
bool getHostMacAddress(const char *, Mac *);