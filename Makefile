#Makefile
all: arp_spoof

arp_spoof: main.o packetheader.o
	g++ -o arp_spoof main.o packetheader.o -lpcap -w -Wall

main.o: main.c

packetheader.o: packetheader.c

clean:
	rm -f send_arp
	rm -f *.o
