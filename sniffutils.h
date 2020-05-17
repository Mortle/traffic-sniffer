#ifndef SNIFFUTILS_H
#define SNIFFUTILS_H

#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>

/* Callback function used in pcap_loop() */
void process_packet(u_char *args,const struct pcap_pkthdr *header,
 const u_char *packet);

/* Print packet payload */
void print_payload(const char *payload, int len);

/* Prints packet payload line */
void print_hex_ascii_line(const u_char *payload, int len, int offset);

#endif
