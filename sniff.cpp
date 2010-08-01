#include "sniff.h"

extern void handle_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
	static int count = 1;			/* packet counter */

	/* declar pointers to packet headers */
	const struct ethernet_header *ethernet;	/* the ethernet header */
	ip_header *ip;				/* the IP header */
	tcp_header *tcp;			/* the TCP header */
	udp_header *uh;
	const char *payload = "";						/* packet payload */

	int size_ip;
	int size_tcp;
	int size_payload = 0;

	printf("\nPacket number %d:\n", count);
	count++;

	/* define ethernet header */
	ethernet = (struct ethernet_header*)(packet);

	/* define ip header offset */
	ip = (struct ip_header*)(packet + SIZE_ETHERNET);
	size_ip = IP_HL(ip)*4;

	if (size_ip < 20){
		printf("	* Invalid IP header length: %u bytes\n", size_ip);
		return;
	}


	/* determine protocol */
	switch(ip->ip_p){
	case IPPROTO_TCP:
		printf("	Protocol: TCP\n");
		/* Packet is TCP */
		/* define tcp header offset */
		tcp = (struct tcp_header*)(packet + SIZE_ETHERNET + size_ip);
		size_tcp = TH_OFF(tcp)*4;
		if (size_tcp < 20){
			printf("	* Invalid TCP header length: %u bytes\n", size_tcp);
			return;
		}
		tcp_handler(tcp,size_tcp,size_ip,packet,payload,size_payload,ip);
		break;
	case IPPROTO_UDP:

	printf("	Protocol: UDP\n");

		/* retrieve the position of the ip header */
		ip = (ip_header *) (packet + 14);

		/* retrieve the position of the udp header */
		uh = (udp_header *) ((u_char*)ip + size_ip + SIZE_ETHERNET);
		udp_handler(payload,packet,uh,ip,size_ip);
		return;
	case IPPROTO_ICMP:
		printf("	Protocol: ICMP\n");
		return;
	case IPPROTO_IP:
		printf("	Protocol: IP\n");
		return;
	default:
		printf("	Protocol: Unknown\n");
		return;
	}

	return;
}
extern void tcp_handler(tcp_header *tcp,int size_tcp,int size_ip, const u_char *packet,const char *payload,int size_payload,ip_header *ip)
{
	FILE *myfile;
	printf("	Src port: %d\n", ntohs(tcp->th_sport));
	printf("	Dst port: %d\n", ntohs(tcp->th_dport));
	myfile = fopen("youtube.dat","a+");
		/* print connection data */
	printf("%d.%d.%d.%d:%d -> %d.%d.%d.%d:%d\n",
		ip->saddr.byte1,
		ip->saddr.byte2,
		ip->saddr.byte3,
		ip->saddr.byte4,
		tcp->th_sport,
		ip->daddr.byte1,
		ip->daddr.byte2,
		ip->daddr.byte3,
		ip->daddr.byte4,
		tcp->th_dport);

	/* define tcp payload (segment) offset */
	payload = reinterpret_cast<const char *>(packet + SIZE_ETHERNET + size_ip + size_tcp);

	/* compute tcp payload (segment) size */
	size_payload = ntohs(ip->ip_len) - (size_ip + size_tcp);

	/* Print payload data, it might be binary so don't treat it as a string */
	if (size_payload > 0) {
		printf("	Payload (%d bytes):\n",size_payload);
		print_payload((const u_char *)payload,size_payload);
			
	}
	fclose(myfile);
	return;
}
extern void udp_handler(const char *payload,const u_char *packet,udp_header *uh,ip_header *ih,int size_ip)
{
	u_short sport,dport;
	FILE *myfile;

	/* convert to host order */
	sport = ntohs(uh->sport);
	dport = ntohs(uh->dport);
	
	/* print connection data */
	printf("%d.%d.%d.%d:%d -> %d.%d.%d.%d:%d\n",
		ih->saddr.byte1,
		ih->saddr.byte2,
		ih->saddr.byte3,
		ih->saddr.byte4,
		sport,
		ih->daddr.byte1,
		ih->daddr.byte2,
		ih->daddr.byte3,
		ih->daddr.byte4,
		dport);
	/* calculate payload */
	myfile = fopen("youtube.dat","a+");
	/* right bitshift to get payload offset */
	payload = reinterpret_cast<const char *>(packet + SIZE_ETHERNET + size_ip + SIZE_UDP );

	/* compute tcp payload (segment) size */
	int size_payload = ntohs(ih->ip_len) - (size_ip + uh->len);

	if (size_payload > 0)
	{
		print_payload((const u_char *)payload,size_payload);
		
	}

	fclose(myfile);
	return;
}
void print_hex_ascii_line(const u_char *payload, int len, int offset)
{

	int i;
	int gap;
	const u_char *ch;

	/* offset */
	printf("%05d   ", offset);
	
	/* hex */
	ch = payload;
	for(i = 0; i < len; i++) {
		printf("%02x ", *ch);
		ch++;
		/* print extra space after 8th byte for visual aid */
		if (i == 7)
			printf(" ");
	}
	/* print space to handle line less than 8 bytes */
	if (len < 8)
		printf(" ");
	
	/* fill hex gap with spaces if not full line */
	if (len < 16) {
		gap = 16 - len;
		for (i = 0; i < gap; i++) {
			printf("   ");
		}
	}
	printf("   ");
	
	/* ascii (if printable) */
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
void print_payload(const u_char *payload, int len)
{

	int len_rem = len;
	int line_width = 16;			/* number of bytes per line */
	int line_len;
	int offset = 0;					/* zero-based offset counter */
	const u_char *ch = payload;

	if (len <= 0)
		return;

	/* data fits on one line */
	if (len <= line_width) {
		print_hex_ascii_line(ch, len, offset);
		return;
	}

	/* data spans multiple lines */
	for ( ;; ) {
		/* compute current line length */
		line_len = line_width % len_rem;
		/* print line */
		print_hex_ascii_line(ch, line_len, offset);
		/* compute total remaining */
		len_rem = len_rem - line_len;
		/* shift pointer to remaining bytes to print */
		ch = ch + line_len;
		/* add offset */
		offset = offset + line_width;
		/* check if we have line width chars or less */
		if (len_rem <= line_width) {
			/* print last line and get out */
			print_hex_ascii_line(ch, len_rem, offset);
			break;
		}
	}

return;
}
