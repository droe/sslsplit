/*
 * arpop.c
 *
 *  Created on: Oct 19, 2016
 *      Author: devel
 */

#include "arpop.h"

static int arp_fd;

int send_arp_request(char *ip, char *netint)
{
	int retVal;
	libnet_t *l;
	char errbuf[LIBNET_ERRBUF_SIZE], target_ip_addr_str[16];
	unsigned int target_ip_addr, src_ip_addr;
	unsigned char mac_broadcast_addr[MAC_LEN] = {0xff, 0xff, 0xff, 0xff,0xff, 0xff};
	unsigned char mac_zero_addr[MAC_LEN] = {0x0, 0x0, 0x0, 0x0, 0x0, 0x0};
	struct libnet_ether_addr *src_mac_addr;
	char *ether_frame;

	arp_fd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
	if( arp_fd == -1 )
	{
		log_err_printf("ARP Socket: %s", strerror(errno));
		return (-1);
	}

	ether_frame = malloc(IP_MAXPACKET);
	if(ether_frame == NULL){
		log_err_printf("Allocation error\n");
		return (-1);
	}

	l = libnet_init(LIBNET_LINK, netint, errbuf);
	if ( l == NULL ) {
		log_err_printf("libnet_init() failed: %s\n", errbuf);
		return (-1);
	}

	/* Getting our own MAC and IP addresses */

	src_ip_addr = libnet_get_ipaddr4(l);
	if ( src_ip_addr == -1 ) {
		log_err_printf("Couldn't get own IP address: %s\n", libnet_geterror(l));
		goto bad;
	}

	src_mac_addr = libnet_get_hwaddr(l);
	if ( src_mac_addr == NULL ) {
		log_err_printf("Couldn't get own MAC address: %s\n", libnet_geterror(l));
		goto bad;
	}

	/* Getting target IP address */
	target_ip_addr = libnet_name2addr4(l, ip, LIBNET_DONT_RESOLVE);

	if ( target_ip_addr == -1 ) {
		log_err_printf("Error converting IP address.\n");
		goto bad;
	}

	/* Building ARP header */

	if ( libnet_autobuild_arp (ARPOP_REQUEST,\
							   src_mac_addr->ether_addr_octet,\
							   (u_int8_t*)(&src_ip_addr), mac_zero_addr,\
							   (u_int8_t*)(&target_ip_addr), l) == -1)
	{
		log_err_printf("Error building ARP header: %s\n", libnet_geterror(l));
		goto bad;
	}

	/* Building Ethernet header */

	if ( libnet_autobuild_ethernet (mac_broadcast_addr, ETHERTYPE_ARP, l) == -1 )
	{
		log_err_printf("Error building Ethernet header: %s\n", libnet_geterror(l));
		goto bad;
	}

	/* Writing packet */

	retVal = libnet_write(l);
	if ( retVal == -1 ){
		log_err_printf("Error writing packet: %s\n", libnet_geterror(l));
		goto bad;
	}

	retVal = 0;
bad:
	libnet_destroy(l);
	free (ether_frame);

	return retVal;
}

int get_arp_response(char *ip, char mac[MAC_LEN])
{

    ARP_PKT *arphdr;
	char *ether_frame;
	int status;
	int i = 0;
	struct timeval tv;

	ether_frame = malloc(IP_MAXPACKET);
	if(ether_frame == NULL){
		log_err_printf("Allocation error\n");
		return (-1);
	}


	tv.tv_sec = 2;
	tv.tv_usec = 0;

	setsockopt(arp_fd, SOL_SOCKET, SO_RCVTIMEO, (char *)&tv,sizeof(struct timeval));
    arphdr = (ARP_PKT *) ether_frame;
    do{
        if ((status = recvfrom (arp_fd, ether_frame, IP_MAXPACKET, 0, NULL, NULL)) < 0) {
            if (errno == EINTR) {
                memset (ether_frame, 0, IP_MAXPACKET * sizeof (char));
                continue;
            }
            else {
               log_err_printf ("recv() failed: %s", strerror(errno));
               close(arp_fd);
               free(ether_frame);
               return (-1);
            }
        }

        if( ((ether_frame[12] << 8) + ether_frame[13]) != ETH_P_ARP ){
        	continue;
        }

        if(ntohs (arphdr->arp_opcode) != ARPOP_REPLY){
        	continue;
        }
    }while(inet_addr(ip) != arphdr->sender_ip );

    memcpy(mac, arphdr->sender_mac, MAC_LEN);

    close(arp_fd);
    free(ether_frame);

    return 0;
}


