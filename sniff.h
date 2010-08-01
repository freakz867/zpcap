#include <pcap.h>
#include <iostream>

/* ethernet headers are exactly 14 bytes */
#define SIZE_ETHERNET 14
/* Ethernet addresses are 6 bytes */
#define ETHER_ADDR_LEN 6
/* Snapshot length (max bytes per packet to capture) */
#define SNAP_LEN 1518
/* define length of UDP header */
#define SIZE_UDP 8
/* 4 bytes IP address */
typedef struct ip_address{
    u_char byte1;
    u_char byte2;
    u_char byte3;
    u_char byte4;
}ip_address;
/* Ethernet Header */
struct ethernet_header {
	u_char ether_dhost[ETHER_ADDR_LEN]; /* destination host */
	u_char ether_shost[ETHER_ADDR_LEN]; /* source host address */
	u_short ether_type;					/* IP, ARP, RARP etc.., */
};
/* ip header */
typedef struct ip_header {
	u_char ip_vhl;				/* version << 4 | header length >> 2*/
	u_char ip_tos;				/* type of service */
	u_short ip_len;				/* total length of packet */
	u_short ip_id;				/* identification */
	u_short ip_off;				/* fragment offset field */
#define IP_RF 0x8000			/* Reserved fragment flag */
#define IP_DF 0x4000			/* Don't fragment - flag */
#define IP_MF 0x2000			/* More fragments - flag */
#define IP_OFFMASK 0x1fff		/* Mask for fragmenting bits */
	u_char ip_ttl;				/* time to live */
	u_char ip_p;				/* protocol */
	u_short ip_sum;				/* checksum */
	ip_address saddr;			/* source address */
	ip_address daddr;			/* destination address */
}ip_header;
/* UDP header */
typedef struct udp_header {
	u_short sport;				/* source port */
	u_short dport;				/* destination port */
	u_short len;				/* datagram length */
	u_short crc;				/* checksum */
}udp_header;


#define IP_HL(ip)		(((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)		(((ip)->ip_vhl) >> 4)

/* TCP header */
typedef u_int tcp_seq;
typedef struct tcp_header{
	u_short th_sport;			/* source port */
	u_short th_dport;			/* destin port */
	tcp_seq th_seq;				/* sequence number */
	tcp_seq th_ack;				/* acknowledgement number */
	u_char th_offx2;			/* data offset, rsvd */
#define TH_OFF(th)		(((th)->th_offx2 & 0xf0) >> 4)
	u_char th_flags;
#define TH_FIN 0x01
#define TH_SYN 0x02
#define TH_RST 0x04
#define TH_PUSH 0x08
#define TH_ACK 0x10
#define TH_URG 0x20
#define TH_ECE 0x40
#define TH_CWR 0x80
#define TH_FLAGS		(TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
	u_short th_win;				/* window */
	u_short th_sum;				/* checksum */
	u_short th_urp;				/* urgent pointer */
}tcp_header;

/* packet handler prototypes */
void handle_packet(u_char *args,const struct pcap_pkthdr *header,const u_char *packet);

/* tcp handler */
void tcp_handler(tcp_header *tcp,int size_tcp,int size_ip, const u_char *packet,const char *payload,int size_payload,ip_header *ip);

/* udp handler */
void udp_handler(const char * payload, const u_char  *packet,udp_header *uh,ip_header *ih,int size_ip);
/* print hex_to_ascii */
void print_hex_ascii_line(const u_char *payload, int len, int offset);
/* print payload */
void print_payload(const u_char *payload, int len);