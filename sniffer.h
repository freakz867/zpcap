#include "pcap.h"

/* 4 bytes IP address */
typedef struct ip_address{
    u_char byte1;
    u_char byte2;
    u_char byte3;
    u_char byte4;
}ip_address;

/* IPv4 header */
typedef struct ip_header{
    u_char  ver_ihl;        // Version (4 bits) + Internet header length (4 bits)
    u_char  tos;            // Type of service 
    u_short tlen;           // Total length 
    u_short identification; // Identification
    u_short flags_fo;       // Flags (3 bits) + Fragment offset (13 bits)
    u_char  ttl;            // Time to live
    u_char  proto;          // Protocol
    u_short crc;            // Header checksum
    ip_address  saddr;      // Source address
    ip_address  daddr;      // Destination address
    u_int   op_pad;         // Option + Padding
}ip_header;

/* UDP header*/
typedef struct udp_header{
    u_short sport;          // Source port
    u_short dport;          // Destination port
    u_short len;            // Datagram length
    u_short crc;            // Checksum
}udp_header;

/* TCP header */
typedef struct tcp_header{
	u_short sport;			//Source Port
	u_short dport;			//Destination Port
	unsigned int seq_num;	//Sequence Number
	unsigned int ack_num;	//Acknowledgement Number

	unsigned char ns;
	unsigned char reserved;
	unsigned char data_offset;

	unsigned char fin;		//finish flag
	unsigned char syn;		//synchron flag
	unsigned char rst;		//reset flag
	unsigned char psh;		//push flag
	unsigned char ack;		//acknowledgement flag
	unsigned char urg;		//urgent flag

	unsigned char ecn;		//ecn-ech flag
	unsigned char cwr;		//congestion window reduced flag

	unsigned short window;  //receive window
	unsigned short checksum;//checksum
	unsigned short urgent_pointer; //urgent pointer
} tcp_header;



/* prototype of the packet handler */
void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data);