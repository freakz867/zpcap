#include "sniff.h"
#include "mitm.h"
#include <stdio.h>

#define PROG_NAME	"ZeroProgCap"
#define PROG_DESC	"General Sniffing Software"
#define PROG_CRIGHT "Copyright (c) 2010 The Zeroprogress Group"
#define PROG_DISCL	"No Warranty"







/* print program description prototype */
void display_description(void);

/* print program usage prototype */
void usage(void);

/*
 * Display the Program's information
 */
void display_description(void)
{
	printf("%s - %s\n",PROG_NAME,PROG_DESC);
	printf("%s\n",PROG_CRIGHT);
	printf("%s\n",PROG_DISCL);
	printf("\n");
	return;
}

/* Print program usage */
void usage(void)
{
	printf("Usage: %s [interface]\n", PROG_NAME);
	printf("\n");
	printf("Options:\n");
	printf("	interface	Listen on <interface> for packets.\n");
	printf("\n");
	return;
}


int main()
{
	
	display_description();
	unsigned char * packet;
	packet = (unsigned char *)malloc(28);
	int ret = construct_packet(packet);
	pcap_if_t *alldevs;
	pcap_if_t *d;
	int inum;
	int i=0;
	pcap_t *adhandle;
	char errbuf[PCAP_ERRBUF_SIZE];
	u_int netmask;
	char packet_filter[] = "";
	struct bpf_program fcode;

    /* Retrieve the device list */
    if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &alldevs, errbuf) == -1)
    {
        fprintf(stderr,"Error in pcap_findalldevs: %s\n", errbuf);
        exit(1);
    }
    
    /* Print the list */
    for(d=alldevs; d; d=d->next)
    {
        printf("%d. %s", ++i, d->name);
        if (d->description)
            printf(" (%s)\n", d->description);
        else
            printf(" (No description available)\n");
    }

    if(i==0)
    {
        printf("\nNo interfaces found! Make sure WinPcap is installed.\n");
        return -1;
    }
    
    printf("Enter the interface number (1-%d):",i);
    scanf_s("%d", &inum);
    
    if(inum < 1 || inum > i)
    {
        printf("\nInterface number out of range.\n");
        /* Free the device list */
        pcap_freealldevs(alldevs);
        return -1;
    }

    /* Jump to the selected adapter */
    for(d=alldevs, i=0; i< inum-1 ;d=d->next, i++);
    
    /* Open the adapter */
    if ( (adhandle= pcap_open(d->name,  // name of the device
                             65536,     // portion of the packet to capture. 
                                        // 65536 grants that the whole packet will be captured on all the MACs.
                             PCAP_OPENFLAG_PROMISCUOUS,         // promiscuous mode
                             1000,      // read timeout
                             NULL,      // remote authentication
                             errbuf     // error buffer
                             ) ) == NULL)
    {
        fprintf(stderr,"\nUnable to open the adapter. %s is not supported by WinPcap\n");
        /* Free the device list */
        pcap_freealldevs(alldevs);
        return -1;
    }
	   
    /* Check the link layer. We support only Ethernet for simplicity. */
    if(pcap_datalink(adhandle) != DLT_EN10MB)
    {
        fprintf(stderr,"\nThis program works only on Ethernet networks.\n");
        /* Free the device list */
        pcap_freealldevs(alldevs);
        return -1;
    }
    
    if(d->addresses != NULL)
        /* Retrieve the mask of the first address of the interface */
        netmask=((struct sockaddr_in *)(d->addresses->netmask))->sin_addr.S_un.S_addr;
    else
        /* If the interface is without addresses we suppose to be in a C class network */
        netmask=0xffffff; 


    //compile the filter
    if (pcap_compile(adhandle, &fcode, packet_filter, 1, netmask) <0 )
    {
        fprintf(stderr,"\nUnable to compile the packet filter. Check the syntax.\n");
        /* Free the device list */
        pcap_freealldevs(alldevs);
        return -1;
    }
    
    //set the filter
    if (pcap_setfilter(adhandle, &fcode)<0)
    {
        fprintf(stderr,"\nError setting the filter.\n");
        /* Free the device list */
        pcap_freealldevs(alldevs);
        return -1;
    }
    
    printf("\nlistening on %s...\n", d->description);
    
    /* At this point, we don't need any more the device list. Free it */
    pcap_freealldevs(alldevs);

	//	for(int y = 0; y < 100; y++){
 //   if (pcap_sendpacket(adhandle, packet, sizeof(packet) /* size */) != 0)
 //   {
 //       fprintf(stderr,"\nError sending the packet: \n", pcap_geterr(adhandle));
 //       return -1;
 //   }
	//}
    
    
    /* start the capture */

    pcap_loop(adhandle, 0, handle_packet, NULL);
    
    return 0;
}
//#include <stdlib.h>
//#include <stdio.h>
//
//#include <pcap.h>
//
//
//void main(int argc, char **argv)
//{
//pcap_t *fp;
//char errbuf[PCAP_ERRBUF_SIZE];
//u_char packet[100];
//int i;
//
//    /* Check the validity of the command line */
//    if (argc != 2)
//    {
//        printf("usage: %s interface (e.g. 'rpcap://eth0')", argv[0]);
//        return;
//    }
//    
//    /* Open the output device */
//    if ( (fp= pcap_open(argv[1],            // name of the device
//                        100,                // portion of the packet to capture (only the first 100 bytes)
//                        PCAP_OPENFLAG_PROMISCUOUS,  // promiscuous mode
//                        1000,               // read timeout
//                        NULL,               // authentication on the remote machine
//                        errbuf              // error buffer
//                        ) ) == NULL)
//    {
//        fprintf(stderr,"\nUnable to open the adapter. %s is not supported by WinPcap\n", argv[1]);
//        return;
//    }
//
//    /* Supposing to be on ethernet, set mac destination to 1:1:1:1:1:1 */
//    packet[0]=0x68;
//    packet[1]=0x7F;
//    packet[2]=0x74;
//    packet[3]=0x15;
//    packet[4]=0xD1;
//    packet[5]=0xC8;
//    
//    /* set mac source to 2:2:2:2:2:2 */
//    packet[6]=0x02;
//    packet[7]=0x02;
//    packet[8]=0x02;
//    packet[9]=0x02;
//    packet[10]=0x02;
//    packet[11]=0x02;
//    
//    /* Fill the rest of the packet */
//    for(i=12;i<100;i++)
//    {
//        packet[i]=i%256;
//    }
//
//    /* Send down the packet */
//    if (pcap_sendpacket(fp, packet, 100 /* size */) != 0)
//    {
//        fprintf(stderr,"\nError sending the packet: \n", pcap_geterr(fp));
//        return;
//    }
//
//    return;
//}