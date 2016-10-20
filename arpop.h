/*
 * arpop.h
 *
 *  Created on: Oct 19, 2016
 *      Author: devel
 */

#ifndef ARPOP_H_
#define ARPOP_H_

#include <sys/socket.h>
#include <sys/types.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <errno.h>
#include <libnet.h>
#include <net/ethernet.h>

#define ARPOP_REPLY 2

#define ETHER_TYPE_FOR_ARP 0x0806
#define HW_TYPE_FOR_ETHER 0x0001
#define OP_CODE_FOR_ARP_REQ 0x0001
#define HW_LEN_FOR_ETHER 0x06
#define HW_LEN_FOR_IP 0x04
#define PROTO_TYPE_FOR_IP 0x0800

#define MAC_LEN (6)

#pragma pack(1)
typedef struct arp_packet
{
    // ETH Header
    char dest_mac[6];
    char src_mac[6];
    unsigned short ether_type;
    // ARP Header
    unsigned short hw_type;
    unsigned short proto_type;
    char hw_size;
    char proto_size;
    unsigned short arp_opcode;
    char sender_mac[6];
    unsigned int sender_ip;
    char target_mac[6];
    unsigned int target_ip;
    char padding[18];
}ARP_PKT;

int get_arp_response(char *ip, char mac[MAC_LEN]);
int send_arp_request(char *ip, char *netint);

#endif /* ARPOP_H_ */
