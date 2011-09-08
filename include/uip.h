#ifndef __UIP_H__
#define __UIP_H__
#include <linux/ip.h>
#include "utype.h"

#define UIP_DEFAULT_TTL 128
#define MIN_IPv4_HLEN 20
#define MAX_IPv4_HLEN 60

#define IP_HLEN(x)  (x->ihl << 2) 
#define IPv4  0x04

#define IP_MORE_FRAG(iph) (ntohs(iph->frag_off) & 0x2000)
#define IP_FRAG_OFF(iph) (ntohs(iph->frag_off) & 0x1FFF)


struct ip_sk
{
  uint8 ttl;
  uint16 id;
};

typedef struct ip_sk tip_sk;
typedef struct ip_sk* pip_sk;
typedef struct ip_sk** ppip_sk;

#endif
