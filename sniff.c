#include "sniff.h"

void print_packet(u_char *arg, const struct pcap_pkthdr* pkthdr,
                      const u_char* packet) {
    static int count = 0;

    printf("Packet Number: %d\n", ++count);
    printf("Recieved Packet Size: %d\n", pkthdr->len); /* Length of header */
    printf("Payload:\n");
    for(int i = 0; i < pkthdr->len; i++) {
      if(isprint(packet[i])) /* Check if the packet data is printable */
        printf("%c ",packet[i]);
      else
        printf(" . ");
      if((i % 16 == 0 && i != 0) || i == pkthdr->len - 1)
        printf("\n");
    }
}
