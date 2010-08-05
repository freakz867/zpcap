#ifndef SNIFF_H
#define SNIFF_H
#include <stdio.h>
#define ARP_HW_TYPE				1	/* Type of Hardware */
#define ARP_REQUEST				1	/* OPCODE for Request*/
#define ARP_REPLY				2	/* OPCODE for Reply */
#define PROTO_LEN				4	/* Length of Protocol Addres */
#define	HWA_LEN					6	/* Length of Hardware Address */
#define ARP_TIMEOUT				600 /* Timeout */
#endif
/* ARP Packet Data */
typedef struct ip_addr{
	unsigned char byte1;
	unsigned char byte2;
	unsigned char byte3;
	unsigned char byte4;
}ip_addr;
struct arp_packet{
	unsigned short hw_type;		/* hardware Type */
	unsigned short p_type;		/* protocol Type */
	unsigned char hwlen;			/* Hardware Length */
	unsigned char p_len;			/* Protocol Length */
	unsigned char hwa[HWA_LEN];	/* Hardware Address */
	unsigned char protolen[PROTO_LEN]; /* Protocol Address */
	unsigned char HW_s;		/* Source Hardware Address */
	unsigned char HW_d;		/* Destination Hardware Address */
	ip_addr src;		/* sender IP address */
	ip_addr dest;	/* destination IP address */
	unsigned short op_code;	/* Type of ARP Packet to send */
};


int construct_packet(unsigned char arp_packet[100]);

