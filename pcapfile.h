#ifndef __PCAP_FILE_H__
#define __PCAP_FILE_H__

#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <libnet.h>
#include "arpop.h"

#define MSS_VAL (1460)
#define MIRROR_TO_INTERFACE (1)


typedef struct pcap_log{
	time_t epoch;
	unsigned int srcIp;
	unsigned int dstIp;
	unsigned short srcPort;
	unsigned short dstPort;
	unsigned int ack;
	unsigned int seq;
	unsigned int mirror;
	char target_mac[MAC_LEN];
} pcap_log_t;


typedef struct pcap_packet_header{
	pcap_log_t packet_info;
} packet_hdr_t;

typedef struct pcap_hdr_s {
        unsigned int magic_number;   /* magic number */
        unsigned short version_major;  /* major version number */
        unsigned short version_minor;  /* minor version number */
        unsigned int  thiszone;       /* GMT to local correction */
        unsigned int sigfigs;        /* accuracy of timestamps */
        unsigned int snaplen;        /* max length of captured packets, in octets */
        unsigned int network;        /* data link type */
} pcap_hdr_t;

typedef struct pcaprec_hdr_s {
        unsigned int ts_sec;         /* timestamp seconds */
        unsigned int ts_usec;        /* timestamp microseconds */
        unsigned int incl_len;       /* number of octets of packet saved in file */
        unsigned int orig_len;       /* actual length of packet */
} pcaprec_hdr_t;


void store_ip_port(pcap_log_t *, char* , char *, char * , char *, int);
int build_ip_packet(void * iohandle, pcap_log_t *pcap, char, char * payload, size_t payloadlen);
int write_pcap_global_hdr(int fd);
int write_payload(void *iohandle, pcap_log_t *from, pcap_log_t *to, char flags, char * payload, size_t payloadlen);
int get_macaddr_of_mirror_ip(char *ip, char *mac, char *netint);

#endif