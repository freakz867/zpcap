#include "mitm.h"
#include "sniff.h"

extern int construct_packet(u_char packet_arp[100])
{
	/* Constructs the packet
	/* set up IP addresses */
	/* src */
	ip_addr arp_src,arp_dest;
	arp_src.byte1 = 192;
	arp_src.byte2 = 168;
	arp_src.byte3 = 1;
	arp_src.byte4 = 1;
	/* destination */
	arp_dest.byte1 = 192;
	arp_dest.byte2 = 168;
	arp_dest.byte3 = 1;
	arp_dest.byte4 = 102;
	/*set up arp struct */
	struct arp_packet arp_test;

	arp_test.hw_type = (unsigned short)1;
	arp_test.p_type = (unsigned short)0x800;
	arp_test.hwlen  = (unsigned char)6;
	arp_test.p_len = (unsigned char)4;
	arp_test.HW_d = (unsigned char)"687F7415D1C7";
	arp_test.HW_s = (unsigned char)"0019212C8646";
	arp_test.src = (ip_addr)arp_src;
	arp_test.dest = (ip_addr)arp_dest;
	arp_test.op_code = (unsigned short)2;
	
	memcpy(packet_arp,(const char *)arp_test.hw_type,sizeof(arp_test.hw_type));
	memcpy(packet_arp,(const char *)arp_test.p_type,sizeof(arp_test.p_type));
	memcpy(packet_arp,(const char *)arp_test.hwlen,sizeof(arp_test.hwlen));
	memcpy(packet_arp,(const char *)arp_test.p_len,sizeof(arp_test.p_len));
	memcpy(packet_arp,(const char *)arp_test.op_code,sizeof(arp_test.op_code));
	memcpy(packet_arp,(const char *)arp_test.HW_s,sizeof(arp_test.HW_s));
	memcpy(packet_arp,(ip_addr)arp_test.src,sizeof(arp_test.src));
	memcpy(packet_arp,(const char *)arp_test.HW_d,sizeof(arp_test.HW_d));
	memcpy(packet_arp,(ip_addr)arp_test.dest,sizeof(arp_test.dest));

	return 1;


}
