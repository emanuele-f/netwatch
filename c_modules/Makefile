.phony: default clean

default: pkt_reader.so arp_scanner.so
clean:
	rm -f *.o *.so arp_scanner pkt_reader
	rm -rf __pycache__

pkt_reader.o: pkt_reader.c headers.h
	gcc -g -Wall -fPIC `pkg-config --cflags python3` -c pkt_reader.c -o pkt_reader.o

pkt_reader.so: pkt_reader.o
	gcc -shared pkt_reader.o -o pkt_reader.so -lpcap `pkg-config --libs python3`

pkt_reader: pkt_reader.o
	gcc -g pkt_reader.o -o pkt_reader -lpcap `pkg-config --libs python3`

arp_scanner.o: arp_scanner.c
	gcc -g -Wall -fPIC `pkg-config --cflags python3` -c arp_scanner.c -o arp_scanner.o

arp_scanner.so: arp_scanner.o
	gcc -shared arp_scanner.o -o arp_scanner.so -ldnet `pkg-config --libs python3`

arp_scanner: arp_scanner.o
	gcc -g arp_scanner.o -o arp_scanner -ldnet `pkg-config --libs python3`
