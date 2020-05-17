#include "sniffer.h"

struct sniff_ip {
  u_char  ip_vhl;                 /* Version << 4 | Header length >> 2 */
  u_char  ip_tos;                 /* Type of service                   */
  u_short ip_len;                 /* Total length                      */
  u_short ip_id;                  /* Identification                    */
  u_short ip_off;                 /* Fragment offset field             */
#define IP_RF 0x8000              /* Reserved fragment flag            */
#define IP_DF 0x4000              /* Dont fragment flag                */
#define IP_MF 0x2000              /* More fragments flag               */
#define IP_OFFMASK 0x1fff         /* Mask for fragmenting bits         */
  u_char  ip_ttl;                 /* Time to live                      */
  u_char  ip_p;                   /* Protocol                          */
  u_short ip_sum;                 /* Checksum                          */
  struct  in_addr ip_src,ip_dst;  /* Src and dst address               */
};

struct sniff_tcp {
        u_short th_sport;               /* Source port                 */
        u_short th_dport;               /* Destination port            */
        tcp_seq th_seq;                 /* Sequence number             */
        tcp_seq th_ack;                 /* Acknowledgement number      */
        u_char  th_offx2;               /* Data offset, rsvd           */
#define TH_OFF(th) (((th)->th_offx2 & 0xf0) >> 4)
        u_char  th_flags;
#define TH_FIN  0x01
#define TH_SYN  0x02
#define TH_RST  0x04
#define TH_PUSH 0x08
#define TH_ACK  0x10
#define TH_URG  0x20
#define TH_ECE  0x40
#define TH_CWR  0x80
#define TH_FLAGS (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
        u_short th_win;                 /* Window */
        u_short th_sum;                 /* Checksum */
        u_short th_urp;                 /* Urgent pointer */
};

WINDOW *win;

void process_packet(u_char *args, const struct pcap_pkthdr *header,
  const u_char *packet) {

	static int count = 1;                   /* packet counter */

	const struct sniff_ip *ip;              /* The IP header */
	const struct sniff_tcp *tcp;            /* The TCP header */
	const char *payload;                    /* Packet payload */

	int size_ip;
	int size_tcp;
	int size_payload;

	wprintw(win, "\nPacket %d:\n", count++);
  wrefresh(win);

	/* Define/compute IP header offset */
	ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
	size_ip = IP_HL(ip)*4;
	if (size_ip < 20) {
		wprintw(win, "Invalid IP header length: %u bytes\n", size_ip);
    wrefresh(win);
		return;
	}

	/* print source and destination IP addresses */
	wprintw(win, "       From: %s\n", inet_ntoa(ip->ip_src));
	wprintw(win, "         To: %s\n", inet_ntoa(ip->ip_dst));
  wrefresh(win);

	/* Determine protocol */
	switch(ip->ip_p) {
		case IPPROTO_TCP:
			wprintw(win, "   Protocol: TCP\n");
			break;
		case IPPROTO_UDP:
			wprintw(win, "   Protocol: UDP\n");
			return;
		case IPPROTO_ICMP:
			wprintw(win, "   Protocol: ICMP\n");
			return;
		case IPPROTO_IP:
			wprintw(win, "   Protocol: IP\n");
			return;
		default:
			wprintw(win, "   Protocol: unknown\n");
			return;
	}
  wrefresh(win);

	/* Define/compute TCP header offset */
	tcp = (struct sniff_tcp*)(packet + SIZE_ETHERNET + size_ip);
	size_tcp = TH_OFF(tcp)*4;
	if (size_tcp < 20) {
		wprintw(win, "Invalid TCP header length: %u bytes\n", size_tcp);
    wrefresh(win);
		return;
	}

	wprintw(win, "   Src port: %d\n", ntohs(tcp->th_sport));
	wprintw(win, "   Dst port: %d\n", ntohs(tcp->th_dport));
  wrefresh(win);

	/* Define/compute TCP payload (segment) offset */
	payload = (char *)(packet + SIZE_ETHERNET + size_ip + size_tcp);

	/* Compute TCP payload (segment) size */
	size_payload = ntohs(ip->ip_len) - (size_ip + size_tcp);

	if (size_payload > 0) {
		wprintw(win, "   Payload: %d bytes\n", size_payload);
    wrefresh(win);
		//print_payload(payload, size_payload);
	}

  return;
}

void print_payload(const char *payload, int len) {

	int len_rem = len;
	int line_width = 16;			/* Number of bytes per line */
	int line_len;
	int offset = 0;					  /* Zero-based offset counter */
	const u_char *ch = (u_char *)payload;

	if (len <= 0)
		return;

	/* Data fits on one line */
	if (len <= line_width) {
		print_hex_ascii_line(ch, len, offset);
		return;
	}

	/* Data spans multiple lines */
	while(1) {
		line_len = line_width % len_rem;            /* Current line length */
		print_hex_ascii_line(ch, line_len, offset); /* Print line          */
		len_rem = len_rem - line_len;               /* Remaining           */
		ch = ch + line_len;                         /* Shift pointer       */
		offset = offset + line_width;               /* Add offset          */

		if (len_rem <= line_width) {                /* Last line           */
			print_hex_ascii_line(ch, len_rem, offset);
			break;
		}
	}

  return;
}

void print_hex_ascii_line(const u_char *payload, int len, int offset) {

	int i;
	int gap;
	const u_char *ch;

	printf("%05d   ", offset); /* Line offset */

	ch = payload;
	for(i = 0; i < len; i++) {
		printf("%02x ", *ch);
		ch++;

		if (i == 7)
			printf(" ");
	}

	if (len < 8)
		printf(" ");

	if (len < 16) {
		gap = 16 - len;
		for (i = 0; i < gap; i++) {
			printf("   ");
		}
	}
	printf("   ");

	/* Ascii if printable */
	ch = payload;
	for(i = 0; i < len; i++) {
		if (isprint(*ch))
			printf("%c", *ch);
		else
			printf(".");
		ch++;
	}

	printf("\n");

  return;
}

void sniffer(WINDOW *window, char *filter, char *device, int num_packets) {
  win = window;
  wprintw(win, "Started capturing...\n");

  char errbuf[PCAP_ERRBUF_SIZE]; /* Error buffer                         */
  pcap_t* descr;                 /*                                      */
  struct bpf_program fp;         /* Compiled filter program (expression) */
  bpf_u_int32 maskp;             /* Subnet mask                          */
  bpf_u_int32 netp;              /* IP                                   */

  /* Get device */
  if(!device[0]) {
    device = pcap_lookupdev(errbuf);

    if(device == NULL) {
      wprintw(win, "%s\n", errbuf);
      wrefresh(win);
      return;
    }
  }

  /* Get the network address and mask */
  pcap_lookupnet(device, &netp, &maskp, errbuf);

  /* Open device for reading in promiscuous mode */
  descr = pcap_open_live(device, BUFSIZ, 1, -1, errbuf);
  if(descr == NULL) {
    wprintw(win, "pcap_open_live(): %s\n", errbuf);
    wrefresh(win);
    return;
  }

  /* Make sure we're capturing on an Ethernet device */
  if (pcap_datalink(descr) != DLT_EN10MB) {
    wprintw(win, "%s is not an Ethernet\n", device);
    wrefresh(win);
    return;
  }

  /* Compile the filter expression */
  if(pcap_compile(descr, &fp, filter, 0, netp) == -1) {
    wprintw(win, "Error calling pcap_compile\n");
    wrefresh(win);
    return;;
  }

  /* Set the filter */
  if(pcap_setfilter(descr, &fp) == -1) {
    wprintw(win, "Error setting filter\n");
    wrefresh(win);
    return;
  }

  /* Loop for callback function */
  pcap_loop(descr, num_packets, process_packet, NULL);

  pcap_freecode(&fp);
  pcap_close(descr);

  return;
}
