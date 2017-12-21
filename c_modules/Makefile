.phony: default

default: pkt_reader.so

pkt_reader.o: pkt_reader.c headers.h
	gcc -g -Wall -fPIC `pkg-config --cflags python2` -c pkt_reader.c -o pkt_reader.o

pkt_reader.so: pkt_reader.o
	gcc -shared pkt_reader.o -o pkt_reader.so -lpcap `pkg-config --libs python2`

pkt_reader: pkt_reader.o
	gcc -g pkt_reader.o -o pkt_reader -lpcap `pkg-config --libs python2`
