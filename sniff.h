#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>

/* Display the contents of the packets accepted by the filter expression */
void print_packet(u_char *arg, const struct pcap_pkthdr* pkthdr,
        const u_char* packet);
