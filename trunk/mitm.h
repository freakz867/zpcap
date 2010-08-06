#ifndef SNIFF_H
#define SNIFF_H
#include <stdio.h>
#define ARP_HW_TYPE				1	/* Type of Hardware */
#define ETH_TYPE				0x806
#define ARP_PROTO_TYPE			0x800
#define ARP_REQUEST				1	/* OPCODE for Request*/
#define ARP_REPLY				2	/* OPCODE for Reply */
#define PROTO_LEN				4	/* Length of Protocol Addres */
#define	HWA_LEN					6	/* Length of Hardware Address */
#define ARP_TIMEOUT				600 /* Timeout */
#endif
/* ARP Packet Data */


typedef struct arp_packet{
	unsigned short hw_type;		/* hardware Type */
	unsigned short p_type;		/* protocol Type */
	unsigned char hwlen;			/* Hardware Length */
	unsigned char p_len;			/* Protocol Length */
	unsigned char hwa[HWA_LEN];	/* Hardware Address */
	unsigned char protolen[PROTO_LEN]; /* Protocol Address */
	unsigned char HW_s[6];		/* Source Hardware Address */
	unsigned char HW_d[6];		/* Destination Hardware Address */
	unsigned char src[4];		/* sender IP address */
	unsigned char dest[4];	/* destination IP address */
	unsigned short op_code;	/* Type of ARP Packet to send */
	unsigned short eh_type;
}arp_packet;



/* Constructs the ARP packet */
int construct_packet(unsigned char * packet,arp_packet arph);
/* Initializes needed structs to pass to packet constructor */
int init_structs(arp_packet * arph,unsigned char hwa[HWA_LEN],
				unsigned char protolen[PROTO_LEN],
				unsigned char src_ip[4],unsigned char dest_ip[4]);

