#ifndef __UTCP_CSUM_H__
#define __UTCP_CSUM_H__

#include "utype.h"
#include <linux/ip.h>
#include <netinet/in.h>
#include <linux/tcp.h>

uint16 tcp_sum_calc(uint16 len_tcp, uint16 src_addr[],uint16 dest_addr[], int padding, uint16 buff[]);
uint16 ip_sum_calc(uint16 len_ip_header, uint16 buff[]);



/* Code by Yogesh */
unsigned short cal_cksum(unsigned short ip_hlen, unsigned short *buff, unsigned int sum);

unsigned short ip_csum(unsigned short *ip_dgram, unsigned int hdr_len);

unsigned short tcp_csum(unsigned int src, unsigned int dst, unsigned short *tcp_seg, unsigned int tcp_len);

typedef struct tcp_pseudo
{
    __u32 src_addr;
    __u32 dst_addr;
    __u8 zero;
    __u8 proto;
    __u16 length;
} pseudo_header;

/* Code by Randhir */
unsigned short ip_checksum(struct iphdr * ip);
unsigned short tcp_checksum(struct iphdr * ip, struct tcphdr * tcp);


#endif
