#ifndef __UTCP_CONFIG_H__
#define __UTCP_CONFIG_H__


#define ACCEPT_ALL

#define UTCP_MAX_SEG 1460
#define UTCP_MAX_SENDQ_BYTES 64000
#define UTCP_MAX_RECVQ_BYTES 64000
/* SENDQ = UTCP_MAX_SENDQ_BYTES/UTCP_MAX_SEG */
#define UTCP_MAX_SENDQ 44
#define UTCP_MAX_RECVQ 44

#define UTCP_MAX_RETRIES 3
#define UTCP_DEF_RTO 3000

#define UTCP_DEF_WSCALE 1


/* TCP Reno Related Options */
/* RFC 2581 : Reno Implementation */
#define UTCP_RENO_IW(tcp_sk) (MIN((tcp_sk->mss<<2), (MAX((tcp_sk->mss<<1), 4380))))
#define UTCP_RENO_SSTHRESH UTCP_MAX_RECVQ_BYTES

#define UTCP_INCOMING_IP_CSUM 0
#define UTCP_INCOMING TCP_CSUM 0


/* IP related options */
#define UTCP_DEF_TTL 128
#define UTCP_DEF_ID 0x1234

#endif
