#include "mitm.h"
#include "sniff.h"

extern int construct_packet(unsigned char * packet)
{


	return 1;


}
extern int init_structs(arp_packet * arph,unsigned char hwa[HWA_LEN],
				unsigned char protolen[PROTO_LEN],
				unsigned char src_ip[4],unsigned char dest_ip[4])
{
	arph->hw_type		= 0x0001;
	arph->p_type		= 0x0800;
	arph->hwlen			= 0x0006;
	arph->p_len			= 0x0004;
	arph->op_code		= 0x0002;
	memcpy(&arph->HW_s,hwa,sizeof(arph->HW_s));
	memcpy(&arph->src,src_ip,sizeof(arph->src));
	

	return 1;
}

