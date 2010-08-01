#include "sniff.h"
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

	pcap_if_t *alldevs;
	pcap_if_t *d;
	int inum;
	int i=0;
	pcap_t *adhandle;
	char errbuf[PCAP_ERRBUF_SIZE];
	u_int netmask;
	char packet_filter[] = "port 80";
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
    
    /* start the capture */

    pcap_loop(adhandle, 0, handle_packet, NULL);
    
    return 0;
}