#include "sniffutils.h"

#define SIZE_ETHERNET 14 /* Ethernet headers size in bytes   */

#define IP_HL(ip) (((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)  (((ip)->ip_vhl) >> 4)

/* TCP header */
typedef u_int tcp_seq;

/* IP header */
struct sniff_ip {
  u_char  ip_vhl;                 /* Version << 4 | Header length >> 2 */
  u_char  ip_tos;                 /* Type of service                   */
  u_short ip_len;                 /* Total length                      */
  u_short ip_id;                  /* Identification                    */
  u_short ip_off;                 /* Fragment offset field             */
  #define IP_RF 0x8000            /* Reserved fragment flag            */
  #define IP_DF 0x4000            /* Dont fragment flag                */
  #define IP_MF 0x2000            /* More fragments flag               */
  #define IP_OFFMASK 0x1fff       /* Mask for fragmenting bits         */
  u_char  ip_ttl;                 /* Time to live                      */
  u_char  ip_p;                   /* Protocol                          */
  u_short ip_sum;                 /* Checksum                          */
  struct  in_addr ip_src,ip_dst;  /* Src and dst address               */
};

/* TCP header */
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
        u_short th_win;                 /* window */
        u_short th_sum;                 /* checksum */
        u_short th_urp;                 /* urgent pointer */
};

void process_packet(u_char *args, const struct pcap_pkthdr *header,
  const u_char *packet) {

	static int count = 1;                   /* packet counter */

	const struct sniff_ip *ip;              /* The IP header */
	const struct sniff_tcp *tcp;            /* The TCP header */
	const char *payload;                    /* Packet payload */

	int size_ip;
	int size_tcp;
	int size_payload;

	printf("\nPacket number %d:\n", count++);

	/* Define/compute IP header offset */
	ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
	size_ip = IP_HL(ip)*4;
	if (size_ip < 20) {
		printf("   * Invalid IP header length: %u bytes\n", size_ip);
		return;
	}

	/* print source and destination IP addresses */
	printf("       From: %s\n", inet_ntoa(ip->ip_src));
	printf("         To: %s\n", inet_ntoa(ip->ip_dst));

	/* Determine protocol */
	switch(ip->ip_p) {
		case IPPROTO_TCP:
			printf("   Protocol: TCP\n");
			break;
		case IPPROTO_UDP:
			printf("   Protocol: UDP\n");
			return;
		case IPPROTO_ICMP:
			printf("   Protocol: ICMP\n");
			return;
		case IPPROTO_IP:
			printf("   Protocol: IP\n");
			return;
		default:
			printf("   Protocol: unknown\n");
			return;
	}

	/* Define/compute TCP header offset */
	tcp = (struct sniff_tcp*)(packet + SIZE_ETHERNET + size_ip);
	size_tcp = TH_OFF(tcp)*4;
	if (size_tcp < 20) {
		printf("   * Invalid TCP header length: %u bytes\n", size_tcp);
		return;
	}

	printf("   Src port: %d\n", ntohs(tcp->th_sport));
	printf("   Dst port: %d\n", ntohs(tcp->th_dport));

	/* Define/compute TCP payload (segment) offset */
	payload = (char *)(packet + SIZE_ETHERNET + size_ip + size_tcp);

	/* Compute TCP payload (segment) size */
	size_payload = ntohs(ip->ip_len) - (size_ip + size_tcp);

	if (size_payload > 0) {
		printf("   Payload (%d bytes):\n", size_payload);
		print_payload(payload, size_payload);
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
