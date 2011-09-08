#ifndef __UTCP_H__
#define __UTCP_H__

#include <stdio.h>
#include <string.h>
#include <linux/ip.h>
#include <netinet/in.h>
#include <linux/tcp.h>
#include <assert.h>
#include "uip.h"
#include "list.h"
#include "utype.h"
#include "utcp_config.h"
#include "utcp_err.h"
#include "timer.h"

#define MIN_TCP_HDR_LEN 20 
#define MAX_TCP_OPT_HLEN 40
#define MAX_TCP_HDR_LEN 60

#define UTCP_FLAG_FIN        0x01
#define UTCP_FLAG_SYN        0x02
#define UTCP_FLAG_RST        0x04
#define UTCP_FLAG_PSH       0x08
#define UTCP_FLAG_ACK        0x10
#define UTCP_FLAG_URG        0x20
#define UTCP_FLAG_ECE        0x40
#define UTCP_FLAG_CWR        0x80

#define FLAG_ACK_SND_UNA_ADV 0x0001
#define FLAG_ACK_RETR_SEG    0x0002
#define FLAG_ACK_WND_UPD     0x0004
#define FLAG_ACK_DATA_ACKED  0x0008
#define FLAG_ACK_DATA        0x0010

#define FLAG_DUP_ACK        (FLAG_ACK_SND_UNA_ADV|FLAG_ACK_WND_UPD|FLAG_ACK_DATA_ACKED|FLAG_ACK_DATA)


#define TCP_HLEN(x) (x->doff << 2) 

typedef struct queue_node* psendQ_node;
typedef struct queue_node* precvQ_node;

typedef struct queue* psendQ;
typedef struct queue* precvQ;

struct soc_addr
{
  uint16 port;
  uint32 addr;
};

typedef struct soc_addr soc_addr_t;

struct recyclehdr
{
  struct iphdr ip_hdr;
  struct tcphdr tcp_hdr;
  char tcp_opt[MAX_TCP_OPT_HLEN];
  uint8 tcp_opt_len;
  /* current implementation does not support IP OPTs */
};

typedef struct recyclehdr* precyclehdr;

struct ofoQ_struct
{
  uint32 len;
  struct tcp_recv_pkt_meta_t *head;
  struct tcp_recv_pkt_meta_t *tail;
};

typedef struct ofoQ_struct ofoQ_t;
typedef struct ofoQ_struct *pofoQ;

struct tcp_callbacks
{
  void (*data_to_app)(void *tcp_sk, uint8* data, uint16 len, void *pktuserptr, void *data_to_app_ptr, void *user_peer_ptr);
  void (*packet_out)(void *tcp_sk, uint8* ippkt, uint16 len, void* packet_out_ptr, void *user_peer_ptr);
  void *data_app_ptr;
  void *packet_out_ptr;
};

typedef struct tcp_callbacks tcp_cb;
typedef struct tcp_callbacks* ptcp_cb;

enum peer_binding
{
  PEER_BIND_FLOW_CTRL = 0x01,
  PEER_BIND_ALL = PEER_BIND_FLOW_CTRL
};

typedef enum peer_binding peer_binding_t;

struct peer_bind
{
  void *tcp_sk;
  peer_binding_t binding;
  void *user_peer_ptr;
};

typedef struct peer_bind peer_bind_t;
typedef struct peer_bind *ppeer_bind;


struct tcp_sk
{
  tip_sk ip_sk;
  /* Dynamic Parameters */ 
  uint32 bytes_enqueued;
  psendQ_node psnduna;
  psendQ_node psndnxt;
  uint32 snduna;
  uint32 sndnxt;
  uint32 bytes_sent;
  uint32 snd_wl1;
  uint32 snd_wl2;
  uint8 quick_ack_mode;

  /* Persistent Parameters */
  soc_addr_t soc_addr[2];
#define tcpsrcport soc_addr[SRC].port
#define tcpdstport soc_addr[DST].port
#define ipsrcaddr soc_addr[SRC].addr
#define ipdstaddr soc_addr[DST].addr
  uint16 mss;
  uint32 isn;
  uint16 snd_wscale;
  uint16 rcv_wscale;

  /* Congestion Related Parameters */
  uint16 iw;
  uint16 lw;
  uint32 cwnd_cnt; /* bytes acked per rtt */
  uint32 cwnd; /* are in bytes */
  uint32 sndwnd;
  uint32 ssthresh;

  /* Retransmission Related */
  uint32 rto;
  uint32 srtt;
  uint32 rttvar;
  uint8 max_retries;

  struct recyclehdr recycle_hdr;

  /* Lists */
  struct queue sendQ;
  uint16 max_sendQ_size;
  struct queue recvQ;
  ofoQ_t ofoQ ;
  uint16 max_recvQ_size;
  int advwnd;
  uint32 recvnxt;

  /* Timers */
  void *probe_timer;

  /* Callback/Userapp related info */
  tcp_cb cb;
  peer_bind_t peer_sk;
};

typedef struct tcp_sk ttcp_sk;
typedef struct tcp_sk* ptcp_sk;
typedef struct tcp_sk** pptcp_sk;

struct tcp_pkt_meta_t
{
  ptcp_sk tcp_sk; /* TCP socket to which this meta belongs */
  void *retr_timer; /* If retr timer started for this meta, retr_timer is non-null */
  
  /* Packet Related Information */
  uint8 *pkt; /* While Sending this start of IP HDR */
  uint16 len; /* Len of pkt */
  uint8 tcp_hlen; /* tcp_hlen present in pkt */
  uint8 ip_hlen; /* ip_hlen present in pkt */
  uint16 tcp_payload; /* length of tcp payload in this packet */
  void *userptr; /* useptr associated with this pkt_meta */
  uint32 start_seq;
  uint32 ack;

  /* Retransmit Related Info */
  uint16 rto;
  uint8 max_retries;
  uint8 no_of_retries;
  uint32 sent_time;
};

typedef struct tcp_pkt_meta_t tcp_pkt_meta;
typedef struct tcp_pkt_meta_t* ptcp_pkt_meta;
typedef struct tcp_pkt_meta_t** pptcp_pkt_meta;

struct tcp_recv_pkt_meta_t
{
  struct tcp_recv_pkt_meta_t *next_recv_meta;
  ptcp_sk tcp_sk; /* TCP socket to which this meta belongs */

  /* Packet Related Information */
  /* Fields are populated in IP layer */
  uint8 *pkt; /* Start of IP header */
  uint16 iplen;
  uint8 ip_hlen;

  /* Fields are populated in TCP layer */
  uint8 *tcppkt; /* start of TCP header */
  uint8 tcp_hlen; /* Total TCP header len and -20 gives the optional header len */
  uint16 ttl_tcp_payload; /* Len of total tcp payload in this segment */
  union {
    uint8 flags;
    uint8 cwr:1;
    uint8 ece:1;
    uint8 urg:1;
    uint8 ack:1;
    uint8 psh:1;
    uint8 rst:1;
    uint8 syn:1;
    uint8 fin:1;
  };
  uint32 start_seq;
  uint32 end_seq;
  uint32 seg_ack;

  /* fields populated in inordering of packet */
  uint16 tcp_valid_len; /* Total non retr bytes in this segment */
  uint8 *tcp_new_payload_start; /* Start of original/non retr payload */
  
  void *userptr; /* Userptr associated with this pkt_meta */
};

typedef struct tcp_recv_pkt_meta_t   tcp_recv_meta;
typedef struct tcp_recv_pkt_meta_t*  ptcp_recv_meta;
typedef struct tcp_recv_pkt_meta_t** pptcp_recv_meta;

struct mig_info
{
  uint32 snduna;
  uint32 recvnxt;
  uint16 snd_wscale;
  uint16 rcv_wscale;
  uint16 mss;
  uint16 wnd;
};
typedef struct mig_info migrate_info;
typedef struct mig_info *pmig_info;

/* Send Related Functions */


int utcp_packetize_buff(ptcp_sk tcp_sk, const uint8 *buff, const uint32 len, const void *buff_handle, uint32 *bytes_copied);

int utcp_append_sendQ(ptcp_sk tcp_sk, ptcp_pkt_meta tcp_meta);

int utcp_purge_sendQ(psendQ sendQptr);
 
int alloc_tcp_meta();

int create_tcp_meta(uint8 *buff, uint32 len, void *buff_handle);

/* Send Related Functions */

int utcp_append_sendQ(ptcp_sk tcp_sk, ptcp_pkt_meta tcp_meta);

int utcp_purge_sendQ(psendQ sendQptr);
 
int alloc_tcp_meta();

int create_tcp_meta(uint8 *buff, uint32 len, void *buff_handle);

/* Receive Related Functions */

static inline utcp_init_recvQ(precvQ recvQptr)
{
  init_queue(recvQptr);
}

int utcp_recv(ptcp_sk tcp_sk, uint8 *buff, uint32 len);

int utcp_try_send(ptcp_sk tcp_sk);
static void utcp_snd_ack(ptcp_sk tcp_sk);
static void utcp_may_send_wndupd(ptcp_sk tcp_sk, int bytes_acked);

/* Stub related declarations */

int utcp_incoming_ip_pkt(ptcp_sk tcp_sk, ptcp_recv_meta recv_meta, uint8* ippkt, uint16 len);

int utcp_incoming_tcp_pkt(ptcp_sk tcp_sk, ptcp_recv_meta recv_meta);
int utcp_incoming_packet(uint8* ippkt, uint16 len, ptcp_sk tcp_sk);


/* Exported APIs */

ptcp_sk create_tcp_sk(uint32 localaddr, uint32 remoteaddr, uint16 localport, uint16 remoteport);

int utcp_send(ptcp_sk tcp_sk, uint8 *buff, uint32 len, void *buff_handle, uint32 *bytes_copied);

int utcp_incoming_packet(uint8* ippkt, uint16 len, ptcp_sk tcp_sk);

int utcp_migrate_socket(ptcp_sk tcp_sk, pmig_info mig_info);

void utcp_register_data_to_app(ptcp_sk tcp_sk, void (*data_to_app)(void *tcp_sk, uint8* data, uint16 len, void *pktuserptr, void *userptr, void *user_peer_ptr), void *userptr);

void utcp_register_packet_out(ptcp_sk tcp_sk, void (*packet_out)(void *tcp_sk, uint8* ippkt, uint16 len, void *packet_out_ptr, void *user_peer_ptr), void *userptr);

void utcp_bind_peer_socks(ptcp_sk tcp_sk1, void*userptr1, ptcp_sk tcp_sk2, void *userptr2, peer_binding_t binding);

void utcp_unbind_peer_socks(ptcp_sk tcp_sk);

#endif
