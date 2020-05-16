#include "sniff.h"

#define NUM_PACKETS 5

int main(int argc, char *argv[]) {
  char *dev;                     /* Capture device name                  */
  char errbuf[PCAP_ERRBUF_SIZE]; /* Error buffer                         */
  pcap_t* descr;                 /*                                      */
  struct bpf_program fp;         /* Compiled filter program (expression) */
  bpf_u_int32 maskp;             /* Subnet mask                          */
  bpf_u_int32 netp;              /* IP                                   */

  // const u_char *packet;
  // struct pcap_pkthdr hdr;
  // struct ether_header *eptr; /* net/ethernet.h        */

  /* Requires filter argument */
  if(argc != 2) {
    fprintf(stdout, "Usage: %s \"expression\"\n", argv[0]);
    return 0;
  }

  /* Get device */
  dev = pcap_lookupdev(errbuf);

  if(dev == NULL) {
    fprintf(stderr, "%s\n", errbuf);
    exit(1);
  }

  /* Get the network address and mask */
  pcap_lookupnet(dev, &netp, &maskp, errbuf);

  /* Open device for reading in promiscuous mode */
  descr = pcap_open_live(dev, BUFSIZ, 1, -1, errbuf);
  if(descr == NULL) {
    printf("pcap_open_live(): %s\n", errbuf);
    exit(1);
  }

  /* Make sure we're capturing on an Ethernet device */
  if (pcap_datalink(descr) != DLT_EN10MB) {
    fprintf(stderr, "%s is not an Ethernet\n", dev);
    exit(1);
  }

  /* Compile the filter expression */
  if(pcap_compile(descr, &fp, argv[1], 0, netp) == -1) {
    fprintf(stderr, "Error calling pcap_compile\n");
    exit(1);
  }

  /* Set the filter */
  if(pcap_setfilter(descr, &fp) == -1) {
    fprintf(stderr, "Error setting filter\n");
    exit(1);
  }

  /* Loop for callback function */
  pcap_loop(descr, NUM_PACKETS, print_packet, NULL);

  pcap_freecode(&fp);
  pcap_close(descr);

  return 0;
}
