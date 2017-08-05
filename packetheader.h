#pragma once
#include <stdint.h>

struct Ethnet_header{
	uint8_t dstMac[6];
	uint8_t srcMac[6];
	uint16_t type;
};

struct Ip4_header{
	uint8_t ver_len;
	uint8_t type;
	uint16_t total_length;
	uint16_t id;
	uint16_t flag_frag;
	uint8_t TTL;
	uint8_t protocol;
	uint16_t checksum;
	uint32_t src;
	uint32_t dst;
	uint8_t opt[40];
};

struct Arp_header{
	uint16_t htype;
	uint16_t ptype;
	uint8_t hlen;
	uint8_t plen;
	uint16_t op;
	uint8_t senderMAC[6];
	uint32_t senderIP;
	uint8_t targetMAC[6];
	uint32_t targetIP;
};

struct Tcp_header{
	uint16_t src_port;
	uint16_t dst_port;
	uint32_t sequence;
	uint32_t ack;
	uint8_t offset;
	uint8_t flags;
	uint16_t window;
	uint16_t checksum;
	uint16_t urgp;
	uint8_t opt[40];
};


static unsigned char ascii2byte(char *val);

int getmyMAC(char* buf, char* dev);
int arp_spoof(char* out_packet, char* in_packet,int sender, int target, char* myMAC);
int check_arp_type(struct Arp_header *arph, uint16_t htype, uint16_t ptype, uint8_t hlen, uint8_t plen );
int analyze_packet( char* packet );
int print_eth(struct Ethnet_header* eth);
int print_Ip4(struct Ip4_header* iph);
int print_Tcp(struct Tcp_header* tcph);
int print_body( uint8_t* start, uint32_t len );
