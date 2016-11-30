#include "pcapfile.h"
#include <errno.h>

int
write_pcap_global_hdr(int fd)
{
	pcap_hdr_t hdr;
	int ret = 0;

	memset(&hdr, 0x0, sizeof(hdr));

	hdr.magic_number = 0xa1b2c3d4;
	hdr.version_major = 2;
	hdr.version_minor = 4;
	hdr.snaplen = 1500;
	hdr.network = 1;

	ret = write(fd, &hdr, sizeof(hdr));
	if(ret != sizeof(hdr)){
		return -1;
	}

	return 0;
}

void
store_ip_port(pcap_log_t *pcap, char* srcip, char *srcport, char * dstip, char *dstport, int mirror)
{
	pcap->srcIp = inet_addr(srcip);
	pcap->srcPort = atoi(srcport);
	pcap->dstIp = inet_addr(dstip);
	pcap->dstPort = atoi(dstport);
	pcap->epoch = time(NULL);
	pcap->seq = 0;
	pcap->ack = 0;
	pcap->mirror = mirror;
}

int
write_packet_into_file(libnet_t *l, int fd)
{
		int c;
	    u_int32_t len;
	    u_int8_t *packet = NULL;
		pcaprec_hdr_t packet_record_hdr;
		struct timeval tv;

	    c = libnet_pblock_coalesce(l, &packet, &len);
	    if (c == - 1){
	        return (-1);
	    }

	    gettimeofday(&tv, NULL);

	    packet_record_hdr.ts_sec = tv.tv_sec;
	    packet_record_hdr.ts_usec = tv.tv_usec;
	    packet_record_hdr.orig_len = packet_record_hdr.incl_len = len;

	    c = write(fd, &packet_record_hdr, sizeof(packet_record_hdr));
	    if(c == sizeof(packet_record_hdr)){
			c = write(fd, packet, len);
			if (c != len){
				snprintf(l->err_buf, LIBNET_ERRBUF_SIZE,
						"libnet_write_link(): only %d bytes written (%s)\n", c,
						strerror(errno));
				c = -1;

			}
	    }
	    else{
	    	c = -1;
	    }

	    if (l->aligner > 0)
	    {
	        packet = packet - l->aligner;
	    }
	    free(packet);

	    libnet_clear_packet(l);

	    return (c);
}

int
write_payload(void *iohandle, pcap_log_t *from, pcap_log_t *to, char flags, char * payload, size_t payloadlen)
{
	int sendsize = 0;

	while(payloadlen > 0){
		payload += sendsize;
		sendsize = payloadlen > MSS_VAL ? MSS_VAL : payloadlen;

		if(build_ip_packet(iohandle, from, flags, payload, sendsize) == -1){
			log_err_printf("Warning: Failed to write to content log: %s\n",
					strerror(errno));
			return -1;
		}
		to->ack += sendsize;

		payloadlen -= sendsize;
	}

	if(build_ip_packet(iohandle, to, TH_ACK, NULL, 0) == -1){
					log_err_printf("Warning: Failed to write to content log: %s\n",
							               strerror(errno));
					return -1;
	}

	return 0;
}

int
build_ip_packet(void *iohandle, pcap_log_t *pcap, char flags, char * payload, size_t payloadlen)
{
    char errbuf[LIBNET_ERRBUF_SIZE];
    static libnet_t *l = NULL;
    libnet_ptag_t t;
    static char enet_src[MAC_LEN] = {0x84,0x34,0xC3,0x50,0x68,0x8A};
    struct libnet_ether_addr *src_mac_addr;

    if(l == NULL){
		l = libnet_init(
				LIBNET_LINK,                            /* injection type */
				pcap->mirror ? iohandle : "lo",                                   /* network interface */
				errbuf);                                /* error buffer */

		if (l == NULL){
			log_err_printf("libnet_init() failed: %s", errbuf);
			goto bad;
		}

		if(pcap->mirror){
			src_mac_addr = libnet_get_hwaddr(l);
			if ( src_mac_addr == NULL ) {
				log_err_printf("Couldn't get own MAC address: %s\n", libnet_geterror(l));
				goto bad;
			}
			memcpy(enet_src, src_mac_addr->ether_addr_octet, sizeof(enet_src));
		}

		libnet_seed_prand(l);
   }

    if(flags & TH_SYN){
    	pcap->seq = libnet_get_prand(LIBNET_PRu32);
    }

    t = libnet_build_tcp(
        pcap->srcPort,                                    /* source port */
        pcap->dstPort,                                    /* destination port */
		pcap->seq,                                 /* sequence number */
        pcap->ack,                                 /* acknowledgement num */
        flags,                                     /* control flags */
        32767,                                      /* window size */
        0,                                          /* checksum */
        0,                                          /* urgent pointer */
        LIBNET_TCP_H + payloadlen,              /* TCP packet size */
	    payload,                                    /* payload */
        payloadlen,                                  /* payload size */
        l,                                          /* libnet handle */
        0);                                         /* libnet id */
    if (t == -1)
    {
    	log_err_printf("Can't build TCP header: %s\n", libnet_geterror(l));
        goto bad;
    }

    t = libnet_build_ipv4(
        LIBNET_IPV4_H + LIBNET_TCP_H + payloadlen,/* length */
      	0,                                          /* TOS */
		libnet_get_prand(LIBNET_PRu16),                                        /* IP ID */
        0x4000,                                          /* IP Frag */
        64,                                         /* TTL */
        IPPROTO_TCP,                                /* protocol */
        0,                                          /* checksum */
        pcap->srcIp,                                     /* source IP */
        pcap->dstIp,                                     /* destination IP */
        NULL,                                       /* payload */
        0,                                          /* payload size */
        l,                                          /* libnet handle */
        0);                                         /* libnet id */
    if (t == -1){
    	log_err_printf("Can't build IP header: %s\n", libnet_geterror(l));
        goto bad;
    }

    t = libnet_build_ethernet(
    	pcap->target_mac,                                   /* ethernet destination */
        enet_src,                                   /* ethernet source */
        ETHERTYPE_IP,                               /* protocol type */
        NULL,                                       /* payload */
        0,                                          /* payload size */
        l,                                          /* libnet handle */
        0);                                         /* libnet id */
    if (t == -1){
    	log_err_printf("Can't build ethernet header: %s\n", libnet_geterror(l));
        goto bad;
    }

    pcap->seq += payloadlen;

    if(pcap->mirror){
    	t = libnet_write(l);
	    libnet_clear_packet(l);
    }
    else{
    	t = write_packet_into_file(l, (int)iohandle);
    }

    if(t == -1){
    	log_err_printf("Can't write packet: %s\n", libnet_geterror(l));
    }

    return t;
bad:
	return -1;
}

int get_macaddr_of_mirror_ip(char *ip, char *mac, char *netint)
{
	if( send_arp_request(ip, netint) == -1 ){
		log_err_printf("Error on sending arp request\n");
		return (-1);
	}

	if( get_arp_response(ip, mac) == -1 ){
		log_err_printf("Couldnt get arp response\n");
		return (-1);
	}

	return 0;
}
