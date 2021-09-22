all: pcap

pcap: main.o my_pcap.o 
	g++ -o main main.o my_pcap.o -lpcap

main.o: my_pcap.h main.cpp

my_pcap.o: my_pcap.h my_pcap.cpp

clean:
	rm -f main
	rm -f *.o