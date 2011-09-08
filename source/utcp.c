#include <utcp.h>
#include "uip.h"
#include "utcp_csum.h"

#define tcp_hdr(meta)  ((struct tcphdr *)(meta->tcppkt))

/* RFC 2988 : Sec 5 */
#define backoff_rto(rto) (rto<<1)

/* RFC 2988 : Sec 5 */
#define max_retransmits(tcp_meta) (tcp_meta->no_of_retries >= tcp_meta->max_retries)

#define printf

/* Static Inline Functions */

static inline void enter_flow_control(ptcp_sk tcp_sk)
{
  tcp_sk->advwnd = 0;
}
static inline void leave_flow_control(ptcp_sk tcp_sk, int bytes_acked)
{
  utcp_may_send_wndupd(tcp_sk, bytes_acked);
}

static inline void enter_peer_flow_control(ptcp_sk tcp_sk)
{
  if(tcp_sk->peer_sk.binding & PEER_BIND_FLOW_CTRL)
  {
    enter_flow_control((ptcp_sk)tcp_sk->peer_sk.tcp_sk);
  }
}

static inline void leave_peer_flow_control(ptcp_sk tcp_sk, int bytes_acked)
{
  if(tcp_sk->peer_sk.binding & PEER_BIND_FLOW_CTRL)
  {
    leave_flow_control((ptcp_sk)tcp_sk->peer_sk.tcp_sk, bytes_acked);
  }
}

static inline int seg_contains_data(ptcp_recv_meta recv_meta)
{
  return (recv_meta->start_seq != recv_meta->end_seq);
}

static inline void enter_quick_ack(ptcp_sk tcp_sk)
{
  tcp_sk->quick_ack_mode = 1;
}

static inline void leave_quick_ack(ptcp_sk tcp_sk)
{
  tcp_sk->quick_ack_mode = 0;
}

static inline int is_quick_ack(ptcp_sk tcp_sk)
{
  return tcp_sk->quick_ack_mode;
}
static inline void utcp_update_rto(ptcp_sk tcp_sk)
{
  tcp_sk->rto = tcp_sk->srtt + MAX(TIMER_GRANUL, (tcp_sk->rttvar<<2));
}

static void utcp_update_rtt_no_ts(ptcp_sk tcp_sk, uint32 start_time)
{
  uint32 prev_rttvar = tcp_sk->rttvar;
  uint32 prev_srtt = tcp_sk->srtt;
  uint32 new_srtt, new_rttvar;

  int rtt = signed_diff(time_now, start_time);
  /* Current RTT measured */

  if (!rtt) {
      rtt = TIMER_GRANUL;
  }
  /* These equations have been derived from RFC 2988 Sec 2 */
  printf("Before: tcp_sk = %u rto = %u rttvar = %u srtt = %u current rtt = %u start = %u\n", tcp_sk, tcp_sk->rto, tcp_sk->rttvar, tcp_sk->srtt, rtt, start_time);

  if(prev_srtt != 0)
  {
    /* Subsequent RTT measure */
    new_rttvar = prev_srtt-rtt;
    if(new_rttvar < 0)
      new_rttvar = -new_rttvar;

    new_rttvar >>= 2;
    new_rttvar += 3*(prev_rttvar>>2);

    tcp_sk->rttvar = new_rttvar;

    tcp_sk->srtt = (7*prev_srtt + rtt)>>3;
  }
  else
  {
    /* First RTT measure */
    tcp_sk->srtt = rtt;
    tcp_sk->rttvar = rtt>>1;
  }

  utcp_update_rto(tcp_sk);
  printf("After: tcp_sk = %u rto = %u rttvar = %u srtt = %u current rtt = %u start = %u\n", tcp_sk, tcp_sk->rto, tcp_sk->rttvar, tcp_sk->srtt, rtt, start_time);
  fflush(stdout);
}

static inline int is_seg_retx(ptcp_pkt_meta tcp_meta)
{
  return !!tcp_meta->no_of_retries;
}

/* Receive Related Static Functions */

static inline void update_tcp_rcvnxt(ptcp_sk tcp_sk, uint32 seq)
{
  tcp_sk->recvnxt = seq;
  return;
}

static inline psendQ_node get_sendQ_head(ptcp_sk tcp_sk)
{
  return(get_qhead(&(tcp_sk->sendQ)));
}

static inline psendQ_node get_sendQ_tail(ptcp_sk tcp_sk)
{
  return(get_qtail(&(tcp_sk->sendQ)));
}

static inline void update_tcp_seqspace(ptcp_sk tcp_sk, ptcp_recv_meta recv_meta)
{
  update_tcp_rcvnxt(tcp_sk, recv_meta->end_seq);
}

static inline uint32 ofoQ_len(ptcp_sk tcp_sk)
{
  return(tcp_sk->ofoQ.len);
}

#define ofoQ_head(tcp_sk) (tcp_sk->ofoQ.head)
#define ofoQ_tail(tcp_sk) (tcp_sk->ofoQ.tail)

static inline void decr_ofoQ_len(ptcp_sk tcp_sk)
{
  tcp_sk->ofoQ.len--;
}
static inline void incr_ofoQ_len(ptcp_sk tcp_sk)
{
  tcp_sk->ofoQ.len++;
}

static inline void insert_head_ofoQ(ptcp_sk tcp_sk, ptcp_recv_meta recv_meta)
{
  recv_meta->next_recv_meta = ofoQ_head(tcp_sk);
  ofoQ_head(tcp_sk) = recv_meta;
  incr_ofoQ_len(tcp_sk);
  if(!ofoQ_tail(tcp_sk))
  {
    ofoQ_tail(tcp_sk) = recv_meta;
  }
}

static inline void insert_tail_ofoQ(ptcp_sk tcp_sk, ptcp_recv_meta recv_meta)
{ 
  if(ofoQ_tail(tcp_sk))
  {
    ofoQ_tail(tcp_sk)->next_recv_meta = recv_meta;
  }
  
  ofoQ_tail(tcp_sk) = recv_meta;

  if(!ofoQ_head(tcp_sk))
  {
    ofoQ_head(tcp_sk) = recv_meta;
  }
  incr_ofoQ_len(tcp_sk);
}
  
static inline void insert_after_ofoQ(ptcp_sk tcp_sk, ptcp_recv_meta prev_meta, ptcp_recv_meta new_meta)
{
  new_meta->next_recv_meta = prev_meta->next_recv_meta;
  prev_meta->next_recv_meta = new_meta;

  if(!new_meta->next_recv_meta)
  {
    ofoQ_tail(tcp_sk) = new_meta;
  }

  incr_ofoQ_len(tcp_sk);
}


static inline int available_recvwnd(ptcp_sk tcp_sk)
{
  return MAX(((int)(tcp_sk->max_recvQ_size - ofoQ_len(tcp_sk)*tcp_sk->mss)), 0);
}

static inline int available_advwnd(ptcp_sk tcp_sk)
{
  return MIN((tcp_sk->advwnd), available_recvwnd(tcp_sk));
}
/* Send Related Functions */

static inline uint32 how_much_to_send(ptcp_sk tcp_sk)
{
  int bytes_to_send = MIN(tcp_sk->cwnd, tcp_sk->sndwnd);
  /* XXX: Revisit in case of zero window */
  return bytes_to_send;
}

static inline void retransmit_backoff(ptcp_pkt_meta tcp_meta)
{
  tcp_meta->rto = backoff_rto(tcp_meta->rto);
  tcp_meta->no_of_retries++;
}

static inline void init_tcp_meta_rto(ptcp_pkt_meta tcp_meta, ptcp_sk tcp_sk)
{
  tcp_meta->rto = tcp_sk->rto;
  tcp_meta->max_retries = tcp_sk->max_retries;
  tcp_meta->no_of_retries = 0;
}

static inline void deinit_tcp_meta_rto(ptcp_pkt_meta tcp_meta)
{
  tcp_meta->rto = 0;
  tcp_meta->max_retries = 0;
  tcp_meta->no_of_retries = 0;
}

static inline struct queue_node *next_node(struct queue_node *node)
{
  return (node)?node->next:NULL;
}

static inline void utcp_init_sendQ(ptcp_sk tcp_sk)
{
  init_queue(&tcp_sk->sendQ);
}

static inline int utcp_sendQ_len(ptcp_sk tcp_sk)
{
  return queue_len(&tcp_sk->sendQ);
}

static inline int utcp_recvQ_len(ptcp_sk tcp_sk)
{
  return queue_len(&tcp_sk->recvQ);
}

static inline int available_sendQ(ptcp_sk tcp_sk)
{
  return(tcp_sk->max_sendQ_size - utcp_sendQ_len(tcp_sk));
}

static inline void *next_qnode(struct queue_node* nodeptr)
{
  return queue_node_next(nodeptr);
}

static inline ptcp_pkt_meta ref_tcp_meta(struct queue_node *node)
{
  return node?node->data:NULL;
}

static inline int len_of_sndnxt(ptcp_sk tcp_sk)
{
  if(!tcp_sk->psndnxt)
    return 0;
  register ptcp_pkt_meta meta = ref_tcp_meta(tcp_sk->psndnxt);
  return (meta->tcp_payload);
}

static inline uint32 end_seq_of_tcp_meta(ptcp_pkt_meta tcp_meta)
{
  return tcp_meta->start_seq + tcp_meta->tcp_payload;
}

static inline uint32 start_seq_of_tcp_meta(ptcp_pkt_meta tcp_meta)
{
  return tcp_meta->start_seq;
}

static inline void update_snduna(ptcp_sk tcp_sk, psendQ_node sndnode, uint32 acked_bytes)
{
  tcp_sk->psnduna = sndnode;
  tcp_sk->snduna += acked_bytes;
}

static inline void update_sndnxt(ptcp_sk tcp_sk, psendQ_node sndnode, uint32 fsend_bytes)
{
  tcp_sk->psndnxt = sndnode;
  tcp_sk->sndnxt += fsend_bytes;
}

static inline int bytes_to_segments(uint32 bytes, uint16 mss)
{
  return MAX(bytes%mss,1);
}

static inline void init_tcp_meta(ptcp_pkt_meta tcp_meta, ptcp_sk tcp_sk)
{
  tcp_meta->tcp_sk = tcp_sk;
  tcp_meta->retr_timer = NULL;
  tcp_meta->pkt = NULL;
  tcp_meta->len = 0;
  tcp_meta->tcp_hlen = 0;
  tcp_meta->ip_hlen = 0;
  tcp_meta->tcp_payload = 0;
  tcp_meta->userptr = 0;
}

static inline ptcp_pkt_meta get_tcp_meta(ptcp_sk tcp_sk)
{
  ptcp_pkt_meta tcp_meta = malloc(sizeof(tcp_pkt_meta));

  if(tcp_meta)
  {
    init_tcp_meta(tcp_meta, tcp_sk);
  }
  return tcp_meta;
}

static inline void free_tcp_meta(ptcp_pkt_meta tcp_meta)
{
  free(tcp_meta);
  return;
}

static inline uint16 get_tcp_hlen(ptcp_sk tcp_sk)
{
  return MIN_TCP_HDR_LEN;
}
  
static inline uint16 get_ip_hlen(ptcp_sk tcp_sk)
{
  return MIN_IPv4_HLEN;
}

static inline uint8 *allocate_ip_pkt(uint16 len)
{
  return malloc(len);
}

static inline void free_ip_pkt(uint8 *pkt)
{
  free(pkt);
}

static inline uint16 get_scaled_recvwnd(ptcp_sk tcp_sk)
{
  return (available_advwnd(tcp_sk)>>(tcp_sk->rcv_wscale));
}

static utcp_tcp_reno(ptcp_sk tcp_sk, int bytes_acked)
{
  if(tcp_sk->cwnd >= tcp_sk->ssthresh)
  {
    /* Cong Avoidance Phase
       Increase cwnd linearly per rtt
     */
    if (tcp_sk->cwnd_cnt >= tcp_sk->cwnd) {
      tcp_sk->cwnd += tcp_sk->mss;
      /* XXX: Cwnd clamping can be put here */
      tcp_sk->cwnd_cnt = 0;
    } else {
      tcp_sk->cwnd_cnt += bytes_acked;
    }
  }
  else
  {
    /* Slow Start Phase
       Increase cwnd exponentially
     */
     tcp_sk->cwnd += bytes_acked;
  }
  printf("STACK: RENO: cwnd = %u, ssthresh = %u cwnd_cnt = %u sndwnd = %u rto = %u\n", tcp_sk->cwnd, tcp_sk->ssthresh, tcp_sk->cwnd_cnt, tcp_sk->sndwnd, tcp_sk->rto);
}

static inline void update_ssthresh(ptcp_sk tcp_sk, uint32 new_val)
{
  tcp_sk->ssthresh = new_val;
}

static inline void set_cwnd_on_reno_expiry(ptcp_sk tcp_sk)
{
  tcp_sk->cwnd = tcp_sk->lw;
}

static void utcp_reno_expiry(ptcp_sk tcp_sk)
{
  /* RTO expiry detected.
     Update the ssthresh and cwnd according to RFC 2581 Sec 3.1 Eq 3
   */

   update_ssthresh(tcp_sk, MAX((tcp_sk->cwnd>>1), (tcp_sk->mss<<1)));

   set_cwnd_on_reno_expiry(tcp_sk);
  printf("STACK: RENO EXPIRY: cwnd = %u, ssthresh = %u cwnd_cnt = %u sndwnd = %u rto = %u\n", tcp_sk->cwnd, tcp_sk->ssthresh, tcp_sk->cwnd_cnt, tcp_sk->sndwnd, tcp_sk->rto);
}

static void init_reno_opts(ptcp_sk tcp_sk)
{
  tcp_sk->cwnd = tcp_sk->iw = UTCP_RENO_IW(tcp_sk);
  tcp_sk->ssthresh = UTCP_RENO_SSTHRESH;
  /* XXX: Revisit this part */
  tcp_sk->lw = UTCP_MAX_SEG;
}

static inline void utcp_cong_avoid(ptcp_sk tcp_sk, int bytes_acked)
{
  utcp_tcp_reno(tcp_sk, bytes_acked);
}

static inline void utcp_cong_rto_expiry(ptcp_sk tcp_sk)
{
  utcp_reno_expiry(tcp_sk);
}

static inline void init_ipv4_hdr(struct iphdr *ip_hdr, ptcp_sk tcp_sk)
{
  ip_hdr->version = IPv4;
  ip_hdr->ihl = MIN_IPv4_HLEN>>2;
  ip_hdr->tos = 0x00;
  ip_hdr->tot_len = 0x00;
  ip_hdr->id = 0x00;
  ip_hdr->frag_off = 0x00;
  ip_hdr->ttl = tcp_sk->ip_sk.ttl;
  ip_hdr->protocol = IPPROTO_TCP;
  ip_hdr->check = 0x00;
  ip_hdr->saddr = htonl(tcp_sk->ipsrcaddr);
  ip_hdr->daddr = htonl(tcp_sk->ipdstaddr);
}

static inline void init_tcp_hdr(struct tcphdr *tcp_hdr, ptcp_sk tcp_sk)
{
  tcp_hdr->source = htons(tcp_sk->tcpsrcport);
  tcp_hdr->dest = htons(tcp_sk->tcpdstport);
  tcp_hdr->seq = tcp_sk->isn;
  tcp_hdr->ack_seq = FALSE;
  tcp_hdr->doff = MIN_TCP_HDR_LEN>>2; 
  tcp_hdr->res1 = 0; 
  tcp_hdr->cwr = 0;
  tcp_hdr->ece = 0; 
  tcp_hdr->urg = 0; 
  tcp_hdr->ack = 0; 
  tcp_hdr->psh = 0; 
  tcp_hdr->rst = 0; 
  tcp_hdr->syn = 0; 
  tcp_hdr->fin = 0; 
  tcp_hdr->window = tcp_sk->iw;
  tcp_hdr->check = 0x0;
  tcp_hdr->urg_ptr = 0x0;
}

static void init_recycle_hdr(ptcp_sk tcp_sk, precyclehdr hdr)
{
  struct iphdr *ip_hdr   = &hdr->ip_hdr;
  struct tcphdr *tcp_hdr = &hdr->tcp_hdr;

  init_ipv4_hdr(ip_hdr, tcp_sk);

  init_tcp_hdr(tcp_hdr, tcp_sk);
  
  hdr->tcp_opt_len = 0;
}

static void inline get_tcp_options(char* buff, uint8 *len, ptcp_sk tcp_sk)
{
  /*XXX - no options supported for now */
  *len = 0;
  return;
}

static void update_tcp_opt_hdr(uint8* opt_hdr, uint8 opt_len, ptcp_sk tcp_sk)
{
  /* XXX - no options supported right now */
  return;
}

/* This function only updates
 * 1. Optional header
 * 2. Mandatory Header Checksum and Window size
 * Nothing else of the header is touched
 * Assumption: TCP meta contains the complete IP packet
 */
static int update_tcp_hdr(ptcp_sk tcp_sk, ptcp_pkt_meta tcp_meta)
{
  uint8 tcp_hlen = tcp_meta->tcp_hlen;
  uint8 ip_hlen = tcp_meta->ip_hlen;
  uint16 tot_len = tcp_meta->len;
  uint8 *ippkt = tcp_meta->pkt;
  uint8 tcp_opt_len = tcp_hlen - MIN_TCP_HDR_LEN;
  uint16 tcp_payload_len = tcp_meta->tcp_payload;

  uint8 *tcp_hdr = ippkt+ip_hlen;
  uint8 *tcp_opt_hdr = tcp_hdr+tcp_opt_len;

  update_tcp_opt_hdr(tcp_opt_hdr, tcp_opt_len, tcp_sk);

  /* Put the Window Size in the TCP header */
  struct tcphdr *thdr = (struct tcphdr *)tcp_hdr;

  thdr->window = htons(get_scaled_recvwnd(tcp_sk));

  /* Create the TCP checksum */
  /* XXX: Revisit the checksum function */
//  thdr->check = htons(tcp_sum_calc((tcp_payload_len + tcp_hlen), (uint16 *)(&tcp_sk->ipsrcaddr), (uint16 *)(&tcp_sk->ipdstaddr), ((tcp_payload_len) & 0x01), (uint16 *)tcp_hdr));
 //   thdr->check = htons(tcp_csum(tcp_sk->ipsrcaddr, tcp_sk->ipdstaddr, (unsigned short *)tcp_hdr, (tcp_payload_len + tcp_hlen)));
 thdr->check = 0;
 thdr->check = tcp_checksum((struct iphdr *)tcp_meta->pkt, (struct tcphdr *)tcp_hdr);

  return UTCP_SUCC;
}

static int update_ip_hdr(ptcp_sk tcp_sk, ptcp_pkt_meta tcp_meta)
{
  uint8 tcp_hlen = tcp_meta->tcp_hlen;
  uint8 ip_hlen = tcp_meta->ip_hlen;
  uint16 tot_len = tcp_meta->len;
  uint8 *ippkt = tcp_meta->pkt;
  uint8 tcp_opt_len = tcp_hlen - MIN_TCP_HDR_LEN;

  uint8 *tcp_hdr = ippkt+ip_hlen;

  /* Update the IP header checksum */
  struct iphdr *ip_hdr = (struct iphdr *)ippkt;

  ip_hdr->check = 0;
//  ip_hdr->check = htons(ip_sum_calc(ip_hlen, (uint16 *)ippkt));
//  ip_hdr->check = htons(ip_csum((unsigned short *)ippkt, ip_hlen));
  ip_hdr->check = ip_checksum((struct iphdr *)ippkt);

  return UTCP_SUCC;
}

static void fill_tcp_hdr(ptcp_sk tcp_sk, precyclehdr hdr, const int flags)
{
  struct tcphdr *tcp_hdr = &hdr->tcp_hdr;

  get_tcp_options(hdr->tcp_opt, &hdr->tcp_opt_len, tcp_sk);

  tcp_hdr->seq = htonl(tcp_sk->isn+tcp_sk->bytes_enqueued);
  tcp_hdr->ack_seq = htonl(tcp_sk->recvnxt);
  tcp_hdr->doff = (MIN_TCP_HDR_LEN+hdr->tcp_opt_len)>>2; 
  tcp_hdr->res1 = 0; 
  tcp_hdr->cwr = 0;
  tcp_hdr->ece = 0; 
  tcp_hdr->urg = (flags & UTCP_FLAG_URG)?1:0; 
  tcp_hdr->ack = (flags & UTCP_FLAG_ACK)?1:0; 
  tcp_hdr->psh = (flags & UTCP_FLAG_PSH)?1:0; 
  tcp_hdr->rst = (flags & UTCP_FLAG_RST)?1:0; 
  tcp_hdr->syn = (flags & UTCP_FLAG_SYN)?1:0; 
  tcp_hdr->fin = (flags & UTCP_FLAG_FIN)?1:0; 
  /* update window and checksum when the packet goes out 
   * tcp_hdr->window = htons(get_scaled_recvwnd(tcp_sk)); 
   * tcp_hdr->check = 0x0; */
  tcp_hdr->urg_ptr = 0x0;

  /* SYN and FIN consumes one sequence number */
  if(tcp_hdr->syn)
  {
    tcp_sk->bytes_enqueued++;
  }
  if(tcp_hdr->fin)
  {
    tcp_sk->bytes_enqueued++;
  }
}

static void fill_ip_hdr(ptcp_sk tcp_sk, precyclehdr hdr, uint16 bufflen)
{
  struct iphdr *ip_hdr = &hdr->ip_hdr;

  ip_hdr->tot_len = htons((MIN_IPv4_HLEN+MIN_TCP_HDR_LEN+hdr->tcp_opt_len+bufflen));
  ip_hdr->id = tcp_sk->ip_sk.id++;
  ip_hdr->frag_off = 0x00;
  /* populate checksum when packet goes out */
}

static inline void fill_tcp_meta(ptcp_pkt_meta tcp_meta, ptcp_sk tcp_sk, precyclehdr hdr)
{
  tcp_meta->len = ntohs(hdr->ip_hdr.tot_len);
  tcp_meta->tcp_hlen = TCP_HLEN((&hdr->tcp_hdr));
  tcp_meta->ip_hlen = IP_HLEN((&hdr->ip_hdr));
  tcp_meta->tcp_payload = tcp_meta->len - tcp_meta->tcp_hlen - tcp_meta->ip_hlen;
  tcp_meta->start_seq = ntohl(hdr->tcp_hdr.seq);
  tcp_meta->ack = ntohl(hdr->tcp_hdr.ack_seq);
}

/* gather_packet
 * This function picks up buff, tcp_hdr, tcp_options hdr and ip_hdr from recycle_hdr
 * Allocates a new buffer
 * Copies the IP hdr + TCP hdr + TCP Opt + buffer
 * Returns the allocated buffer if SUCCESS
 * NULL if FAILURE;
 */
static uint8* gather_packet(const uint8 *buff, const uint16 bufflen, precyclehdr hdr)
{
  struct iphdr *ip_hdr = &hdr->ip_hdr;
  struct tcphdr *tcp_hdr = &hdr->tcp_hdr;

  uint8 ip_hlen = IP_HLEN(ip_hdr);
  uint8 tcp_hlen = TCP_HLEN(tcp_hdr);
  
  int len_to_alloc = ntohs(ip_hdr->tot_len);

  uint8 *pkt = NULL;
  uint8 *orig_pkt = NULL;

  assert((ip_hlen + tcp_hlen + bufflen) == len_to_alloc);

  orig_pkt = pkt = allocate_ip_pkt(len_to_alloc);

  if(!pkt)
  {
    return NULL;
  }
  
  /*1. Copy IP header */
  memcpy(pkt, ip_hdr, ip_hlen);
  pkt += ip_hlen;

  /*2. Copy MIN TCP header */
  memcpy(pkt, tcp_hdr, MIN_TCP_HDR_LEN);
  pkt += MIN_TCP_HDR_LEN;

  /*3. Copy optional TCP header if any */
  if(hdr->tcp_opt_len)
  {
    memcpy(pkt, hdr->tcp_opt, hdr->tcp_opt_len);
    pkt += hdr->tcp_opt_len;
  }

  /*4. Copy payload buffer if any */
  if(bufflen)
  {
    memcpy(pkt, buff, bufflen);
    pkt += hdr->tcp_opt_len;
  }

  return orig_pkt;
}

static int prepare_pkt_to_send_out(ptcp_sk tcp_sk, ptcp_pkt_meta tcp_meta)
{
  int ret;

  ret = update_tcp_hdr(tcp_sk, tcp_meta);

  if(unlikely(ret == UTCP_ERR))
  {
    goto _failure;
  }

  ret = update_ip_hdr(tcp_sk, tcp_meta);
  
  if(unlikely(ret == UTCP_ERR))
  {
    goto _failure;
  }

_failure:
  return ret;
}


int utcp_abort_connection(ptcp_sk tcp_sk, ptcp_pkt_meta tcp_meta)
{
  /* XXX: Revisit this function */
  return UTCP_SUCC;
}

/* Retransmission Related Functions */
static int stop_retransmit_timer(ptcp_pkt_meta tcp_meta)
{
  if(unlikely(remove_timer(tcp_meta->retr_timer)<0))
  {
      assert(0);
    return UTCP_ERR;
  }

  deinit_tcp_meta_rto(tcp_meta);
  tcp_meta->retr_timer = NULL;
  
  return UTCP_SUCC;
}

static int modify_retransmit_timer(ptcp_pkt_meta tcp_meta, uint16 newrto)
{
  if(unlikely(!tcp_meta || !tcp_meta->retr_timer || !newrto))
  {
      assert(0);
    return UTCP_ERR;
  }

  if(unlikely(modify_timer_val(tcp_meta->retr_timer, newrto)<0))
  {
      assert(0);
    return UTCP_ERR;
  }

  tcp_meta->rto = newrto;

  return UTCP_SUCC;
}




/* utcp_retransmit_pkt
 * 1. if Max retries, abort the connection
 * 2. else sends the tcp_meta on the network
 * 3. Update the RTO and no of retries for this TCP meta
 * 4. restarts the retransmission timer
 *
 * returns 
 * UTCP_SUCC: if segement successfully sent and timer restarted
 * UTCP_ERR: if retransmit times out and connection is aborted
 */

int utcp_retransmit_pkt(ptcp_sk tcp_sk, ptcp_pkt_meta tcp_meta)
{
  int ret;

  /* 1. If max retransmits exceeded, abort the connection */
  if(max_retransmits(tcp_meta))
  {
    ret = utcp_abort_connection(tcp_sk, tcp_meta);
    assert(0);
    return UTCP_ERR;
  }

  /* 2. We still within our limit to retransmit the packet
   * Retransmit it
   */

   printf("STACK: Retx Expiry: RTO = %u No of Retried = %d Current RTO = %u\n", tcp_meta->rto, tcp_meta->no_of_retries, tcp_sk->rto);
   ret = utcp_send_one_pkt(tcp_sk, tcp_meta);

   if(unlikely(ret == UTCP_ERR))
   {
     /* Retransmit Packet could not be sent out */
     /* XXX: Revisit if needed 
      * Current Behavior, still restart the TCP timer and try send this
      * segment on the next RTO expiry
      * It is as if the packet is again lost on the network
      * */
       assert(0);
   }

   /* 3. Successfully sent the pkt out
    * Now backoff the retransmission timer
    */
   retransmit_backoff(tcp_meta);

   /* 4. Restart the timer with new RTO value */
   modify_retransmit_timer(tcp_meta, tcp_meta->rto);

   /* 5. Invoke Cong Algo as we detected RTO expiry */
   utcp_cong_rto_expiry(tcp_sk);

   printf("STACK: Retx Expiry: New RTO = %u New No of Retried = %d \n", tcp_meta->rto, tcp_meta->no_of_retries);

   return UTCP_SUCC;
}

void utcp_retransmit_expiry(void *tcp_pkt_meta)
{
  ptcp_pkt_meta tcp_meta = (ptcp_pkt_meta)tcp_pkt_meta;

  if(unlikely(!tcp_meta || !tcp_meta->tcp_sk))
  {
    return;
  }
  ptcp_sk tcp_sk = tcp_meta->tcp_sk;

  utcp_retransmit_pkt(tcp_sk, tcp_meta);

  return;
}

/* start_retransmit_timer
 * This function starts the retransmission timer for tcp_meta
 * The RTO from tcp_sk is referred.
 * It enqueues the tcp_meta and its callback function in the timerwheel
 * Also initializes the retramission parameters like no_of_retries.
 *
 * On successful starting the timer
 * returns UTCP_SUCC
 * else
 * UTCP_ERR
 */
int start_retransmit_timer(ptcp_sk tcp_sk, ptcp_pkt_meta tcp_meta)
{

  /* Start the retransmit timer for tcp_meta */

  init_tcp_meta_rto(tcp_meta, tcp_sk);
  
  tcp_meta->retr_timer = (void *)add_one_shot_timer(utcp_retransmit_expiry, tcp_meta, tcp_sk->rto);

  if(unlikely(!tcp_meta->retr_timer))
  {
    goto _failure;
  }

  return UTCP_SUCC;

_failure:
  assert(0);
  return UTCP_ERR;
}

/* append_retransmit
 * 1. takes the node which needs to be updated in retranmisssion queue
 * 2. Start the retransmission timer for this node
 *
 * return val
 * UTCP_SUCC: if both actions above succeeds
 * UTCP_ERR: if either of the above action fails
 *
 * the socket sendQ is the only sendQ we have
 * Retransmit Queue is pseudo Q - it is just the difference between
 * snduna and psndnxt.
 * As soon as psndnxt is updated, the node virtually is inserted in retransmitQ
 */

int append_retransmit(ptcp_sk tcp_sk, psendQ_node sndnode)
{
  if(unlikely((!tcp_sk|| !sndnode || !sndnode->data)))
  {
      assert(0);
    return UTCP_ERR;
  }
  int ret;
  ptcp_pkt_meta tcp_meta = ref_tcp_meta(sndnode);

  ret = start_retransmit_timer(tcp_sk, tcp_meta);
  
  if(ret == UTCP_ERR)
  {
      assert(0);
    goto _failure;
  }

  if(!tcp_sk->psnduna)
  {
    /* snduna was never updated */
    update_snduna(tcp_sk, sndnode, 0);
  }

_failure:
  return ret;
}

/* remove_from_retransmit
   This function undoes the things done by append_retransmits
   1. Takes the node to be dequeued from retransmit queue
   2. Stop the retransmission timer
 */

int remove_from_retransmit(ptcp_sk tcp_sk, ptcp_pkt_meta tcp_meta)
{
  int ret = UTCP_ERR;
  if(unlikely((!tcp_sk|| !tcp_meta)))
  {
      assert(0);
    return UTCP_ERR;
  }
  
  ret = stop_retransmit_timer(tcp_meta);
  
  if(ret == UTCP_ERR)
  {
    assert(0);
    goto _failure;
  }

_failure:
  return ret;
}

/* External APIs */

static void dealloc_tcp_meta(ptcp_pkt_meta tcp_meta)
{
  if(tcp_meta->retr_timer)
  {
    /* Step 2. Stop and remove retransmit timer */
    remove_from_retransmit(tcp_meta->tcp_sk, tcp_meta);
  }

  if(tcp_meta->pkt)
  {
    free_ip_pkt(tcp_meta->pkt);
    tcp_meta->pkt = NULL;
  }

  /* XXX: Can indicate to app if meta is getting freed */
  free_tcp_meta(tcp_meta);
}

static void purge_sendQ(ptcp_sk tcp_sk)
{
  psendQ_node sndhead;
  psendQ sendQ = &tcp_sk->sendQ;

  pptcp_pkt_meta tcp_meta;

  while((sndhead = get_sendQ_head(tcp_sk)))
  {
    dequeue(sendQ, (void **)tcp_meta);
    dealloc_tcp_meta(*tcp_meta);
  }
}


/* utcp_send
 * This function takes the buff, len and associated buff_handle
 * from caller.
 * This function does following
 * 1. Try to enqueue the received buff in socket send queue
 * 2. Try to send the packets on the network if congestion algo allows.
 *
 * This function will create the IP packets from the buff.
 * If there are multiple IP packets created from single buff, it will copy buff_handle
 * to every IP packet meta header. (see packetize_buff function)
 * 
 * Return Val:
 * -1 / UTCP_ERR : If no byte was enqueued to SendQ
 * Non zero integer: Indicates how many bytes from buff are enqueued in the socket.
 *
 */

int utcp_send(ptcp_sk tcp_sk, uint8 *buff, uint32 len, void *buff_handle, uint32 *bytes_copied)
{
  int retval = UTCP_SUCC;
  
  /* Basic Checks */
  if(unlikely((!tcp_sk) || (!buff)))
  {
    retval = UTCP_ERR;
    assert(0);
    goto _failure;
  }

  /* Step 1. Check if we can accomodate all or some part buff in our SendQ 
   * If yes, how much can be accomodated will be noted later after packetization
   * If no, failure and go out 
   */

#ifndef ACCEPT_ALL

  if(available_sendQ(tcp_sk) <= 0)
  {
    retval = UTCP_ERR;
    assert(0);
    goto _failure;
  }
#endif
  /* Step 2. Packetize the application buffer in MSS sized chunks
   * Enqueue the packetized chunks in the SendQ
   */

  retval = utcp_packetize_buff(tcp_sk, buff, len, buff_handle, bytes_copied);
  if(retval != UTCP_SUCC)
  {
    if(retval == UTCP_SEND_FULL)
      enter_peer_flow_control(tcp_sk);
    goto _failure;
  }


  /* Step 3. Try to Send on the network
   */
  utcp_try_send(tcp_sk);


_failure:
  return retval;
}

/* utcp_remove_sendQ
   This function takes the sndQ node which needs to be dequeud from 
   SendQ

   return val:
    UTCP_SUCC: On successfull dequeue
    UTCP_ERR: If failure
*/

int utcp_remove_sendQ(ptcp_sk tcp_sk, ptcp_pkt_meta tcp_meta)
{
  psendQ sendQptr = &tcp_sk->sendQ;
  ptcp_pkt_meta tmp_meta;

  if(dequeue(sendQptr, (void **)(&tmp_meta)) != 0)
  {
    goto _failure;
  }

  /* Debug Check */
  assert( (tmp_meta) == tcp_meta);

  return UTCP_SUCC;

_failure:
  assert(0);
  return UTCP_ERR;
}

 
/* utcp_append_sendQ
 * This function takes the completely filled tcp_meta
 * and enqueues the same in the socket SendQ
 *
 * Return Val
 * UTCP_SUCC : on successfully enqueued
 * UTCP_ERR : If not enqueued
 */

int utcp_append_sendQ(ptcp_sk tcp_sk, ptcp_pkt_meta meta)
{
  psendQ sendQptr = &tcp_sk->sendQ;

#ifndef ACCEPT_ALL
  if(available_sendQ(tcp_sk) <= 0)
  {
    goto _failure;
  }
#endif

  if(enqueue(sendQptr, meta) != 0)
  {
    goto _failure;
  }

  if(!tcp_sk->psndnxt)
  {
    update_sndnxt(tcp_sk, get_sendQ_tail(tcp_sk), 0);
  }

  /* Successfully enqueued in the sendQ
   * Update the bytes enqueued
   * This number is used in sending the packet out
   * This is used as the Relative Sequence number
   */

  tcp_sk->bytes_enqueued += (meta->len - meta->tcp_hlen - meta->ip_hlen);

  return UTCP_SUCC;

_failure:
  assert(0);
  return UTCP_ERR;
}

/* utcp_packetize_buff
 * Does two main things
 * A. Segmentize the buff
 * B. Enqueue in socket SendQ
 *
 * 1. Create the mss sized segments from buff
 * 2. create IP packet from mss sized segments
 * 3. enqueue the IP packets to socket sendQ
 * 4. Also attach the tcp_meta to each IP packet
 * 5. Include buff_handle to each tcp_meta with each IP packet
 *
 * Return Val:
 * UTCP_ERR if Failure
 * Non-zero integer if success = No of bytes enqueued in socket SendQ
 */

int utcp_packetize_buff(ptcp_sk tcp_sk, const uint8 *buff, const uint32 len, const void *buff_handle, uint32 *bytes_copied)
{
  int bytes_remaining = len;
  uint8 *curr_buff = (uint8 *)buff;
  int copied;
  ptcp_pkt_meta meta;
  int ret = UTCP_SUCC;

  while(bytes_remaining)
  {
    copied = 0;
    meta = NULL;

    copied = create_tcp_meta_from_buff(tcp_sk, curr_buff, bytes_remaining, &meta, UTCP_FLAG_ACK);

    if(copied <= 0)
    {
      break;
    }
    /* optionally call the registered function to update the userptr */
    meta->userptr = (void *)buff_handle;

    if(utcp_append_sendQ(tcp_sk, meta) == UTCP_ERR)
    {
      /* Packet not enqueued 
       * Forget current meta
       */
      dealloc_tcp_meta(meta);
      assert(0);
      break;
    }

    bytes_remaining -= copied;
    curr_buff += copied;
    if(available_sendQ(tcp_sk) <= 0)
    {
      ret = UTCP_SEND_FULL;
    }
  }

  *bytes_copied = len-bytes_remaining;

  return ret;
}


int create_pkt_from_buff(ptcp_sk tcp_sk, const uint8 *buff, const int bufflen, ptcp_pkt_meta tcp_meta, int tcp_flags)
{
  precyclehdr hdr = &tcp_sk->recycle_hdr;

  fill_tcp_hdr(tcp_sk, hdr, tcp_flags);
  
  fill_ip_hdr(tcp_sk, hdr, bufflen);
  
  tcp_meta->pkt = gather_packet(buff, bufflen, hdr);

  if(!tcp_meta->pkt)
  {
    goto _failure;
  }

  fill_tcp_meta(tcp_meta, tcp_sk, hdr);

  return UTCP_SUCC;

_failure:
  assert(0);
  return UTCP_ERR;
}

/* create_tcp_meta_from_buff
 * This function creates the IP packet from the given buff
 * It copies max MSS sized data from buff
 * Creates the tcp_meta struct for the packet and populates it.
 *
 * Return Val:
 * 0 - Error, no bytes copied
 * positive integer, how many bytes from buffer are copied (packetized)
 *
 * *meta is populated and returned.
 */

int create_tcp_meta_from_buff(ptcp_sk tcp_sk, const uint8 *buff, const int len, pptcp_pkt_meta meta, int flags)
{
  int bytes_copied = MIN(tcp_sk->mss, len); /* Assume success */
  ptcp_pkt_meta tcp_meta;
  int ret;

  tcp_meta = get_tcp_meta(tcp_sk);

  if(unlikely((!tcp_meta)))
  {
    bytes_copied = 0;
    goto _failure;
  }

  ret = create_pkt_from_buff(tcp_sk, buff, bytes_copied, tcp_meta, flags);

  if(unlikely((ret == UTCP_ERR)))
  {
      assert(0);
    /* Free TCP Meta Here */
    dealloc_tcp_meta(tcp_meta);
    tcp_meta = NULL;
    bytes_copied = 0;
    goto _failure;
  }

_failure:
  *meta = tcp_meta;
  return bytes_copied;
}


/* utcp_try_sen
 * This function takes the tcp_sk structure.
 * 1. Check if congestion algorithm allows to send on the network
 * 2. check if we have data to send
 * 3. Try sending on the network
 * 4. Start the retransmission timer for the packets sent on the network
 * 5. update the sndnxt in tcp_sk
 * 
 * Can also be invoked from congestion algorithm on the receipt of ACK.
 * 
 * Returns the number of bytes it could send out
 *
 */
int utcp_try_send(ptcp_sk tcp_sk)
{
  int bytes_to_send = how_much_to_send(tcp_sk);
  int orig_bytes_to_send = bytes_to_send;
  int ret;
  psendQ_node psndnxt = tcp_sk->psndnxt;

  while(psndnxt)
  {
    ptcp_pkt_meta tcp_meta = ref_tcp_meta(psndnxt);
    if (tcp_meta->tcp_payload > bytes_to_send) {
        break;
    }
    ret = append_retransmit(tcp_sk, psndnxt);
    if(ret == UTCP_ERR)
    {
      assert(0);
      break;
    }
    ret = utcp_send_one_pkt(tcp_sk, tcp_meta);
    if(ret == UTCP_ERR)
    {
      assert(0);
      /* Packet not sent out
       * Remove packet from retransmit queue
       */
      remove_from_retransmit(tcp_sk, tcp_meta);
      break;
    }
    bytes_to_send -= tcp_meta->tcp_payload;
    psndnxt = next_node(psndnxt);
  }
  /* Update the tcp_sk->psndnxt so that next send happens from here */
  update_sndnxt(tcp_sk, psndnxt, orig_bytes_to_send - bytes_to_send);
  /* Also note the total bytes sent till now */
  tcp_sk->bytes_sent += (orig_bytes_to_send - bytes_to_send);
  return (orig_bytes_to_send - bytes_to_send);
}

/* utcp_send_one_pkt 
 * This function takes tcp_meta as the packet to be sent out
 * It tries to send the TCP meta on the network
 * The packet before going on the network has to be updated with 
 * checksum, window etc
 *
 * On succ returns: UTCP_SUCC
 * On failure returns : UTCP_ERR
 * 
 */

int utcp_send_one_pkt(ptcp_sk tcp_sk, ptcp_pkt_meta tcp_meta)
{
  if(unlikely((!tcp_sk) || (!tcp_meta)))
  {
    return UTCP_ERR;
  }
  int ret;

  ret = prepare_pkt_to_send_out(tcp_sk, tcp_meta);

  if(ret == UTCP_ERR)
  {
        assert(0);
    goto _failure;
  }

  tcp_meta->sent_time = time_now;

  ret = utcp_device_send(tcp_sk, tcp_meta, tcp_meta->pkt, tcp_meta->len);
 
_failure:
  return ret;
}

/* Receive Related Functions */

int utcp_data_to_app(ptcp_sk tcp_sk, ptcp_recv_meta recv_meta)
{
  tcp_sk->cb.data_to_app(tcp_sk, recv_meta->tcp_new_payload_start, recv_meta->tcp_valid_len, recv_meta->userptr, tcp_sk->cb.data_app_ptr, tcp_sk->peer_sk.user_peer_ptr);
  return UTCP_SUCC;
}

static inline void head_trim_recv_meta(ptcp_recv_meta recv_meta, int overlap)
{
  if(overlap > 0)
  {
    recv_meta->start_seq += overlap;
    recv_meta->tcp_new_payload_start += overlap;
    recv_meta->tcp_valid_len -= overlap;
    recv_meta->end_seq = recv_meta->start_seq + recv_meta->tcp_valid_len;
  }
}

static inline ptcp_recv_meta alloc_recv_meta(ptcp_sk tcp_sk)
{
  ptcp_recv_meta recv_meta = (ptcp_recv_meta)malloc(sizeof(tcp_recv_meta));

  if(recv_meta) 
  {
    memset(recv_meta, 0, sizeof(tcp_recv_meta));
    recv_meta->tcp_sk = tcp_sk;
  }
  return recv_meta;
}

static inline void alloc_ip_pkt_recv_meta(ptcp_recv_meta recv_meta, uint8* ippkt, uint16 len)
{
  recv_meta->pkt = ippkt;
  recv_meta->iplen = len;
}

static inline void free_ip_pkt_recv_meta(ptcp_recv_meta recv_meta)
{
 /* XXX: Free Received IPPKT here */
 recv_meta->pkt = NULL;
 recv_meta->iplen = 0;
}

static inline void free_recv_meta(ptcp_recv_meta recv_meta)
{
  free(recv_meta);
}

/* fill_recv_meta
   This function takes the packet from TCP header onwards
   And updates the recv_meta with all tcp related information

   Assumption:"
   IP pkt parsing is done
   Recv Meta is updated with IP related info

   len = len of tcp_hdr + len of tcp payload
*/

static void fill_recv_meta(ptcp_sk tcp_sk, ptcp_recv_meta recv_meta, uint8* tcp_hdr, uint16 len)
{
}

static inline void  destroy_recv_meta(ptcp_recv_meta recv_meta)
{
  free_ip_pkt_recv_meta(recv_meta);
  free_recv_meta(recv_meta);
}

static inline void remove_ofoQ_head(ptcp_sk tcp_sk)
{
  ptcp_recv_meta tmp_meta;
  tmp_meta = ofoQ_head(tcp_sk);

  ofoQ_head(tcp_sk) = tmp_meta->next_recv_meta;
  decr_ofoQ_len(tcp_sk);

  destroy_recv_meta(tmp_meta);
}

/* purge_recvQ 
   This function will clean up the complete ofoQ
 */
static inline void purge_recvQ(ptcp_sk tcp_sk)
{
  while(ofoQ_len(tcp_sk))
    remove_ofoQ_head(tcp_sk);
}

int utcp_ofo_queue(ptcp_sk tcp_sk, ptcp_recv_meta recv_meta)
{
  ptcp_recv_meta next_meta, prev_meta;
  uint32 new_seq, new_end;
    
  
  recv_meta->tcp_valid_len = recv_meta->ttl_tcp_payload;
  recv_meta->tcp_new_payload_start = recv_meta->tcppkt + recv_meta->tcp_hlen;

  /* Step 1. Here because we didnt hand over the packet to app 
   * and curr pkt != rcvnxt
   * 
   * Step 1a: Find the right place to insert the received packet
   * Fast path - 1. If list empty insert and return
   *             2. check the tail and insert at tail if seq num permit
   *             and return
   */

  if(!ofoQ_len(tcp_sk))
  {
    /* FAST PATH for inserting at head */
    insert_head_ofoQ(tcp_sk, recv_meta);
    return UTCP_SUCC;
  }

  if(!before((ofoQ_tail(tcp_sk)->end_seq), recv_meta->start_seq))
  {
    /* FAST PATH for inserting at TAIL  if seq num permits it */
    insert_tail_ofoQ(tcp_sk, recv_meta);
    return UTCP_SUCC;
  }

  /* Step2 :Slow path - Find out the node after which the current recv_meta
   * should be inserted
   */

  next_meta = ofoQ_head(tcp_sk);
  prev_meta = NULL;
  new_seq = recv_meta->start_seq;
  new_end = recv_meta->end_seq;

  while((next_meta) && (!after(new_seq, next_meta->start_seq)))
  {
    prev_meta = next_meta;
    next_meta = next_meta->next_recv_meta;
  }
  /* recv_meta to be inserted in between prev_meta and next_meta */

  insert_after_ofoQ(tcp_sk, prev_meta, recv_meta);

  /* Step 3. - Head trim if required
   */
  int overlap = signed_diff(prev_meta->end_seq, new_seq);
  head_trim_recv_meta(recv_meta, overlap);
  
  /* Step 4. - Find out the post overlapped pkts
   *           1. If the enqueued pkts completey overlaps, dequeue the already enqueued pkts
   *           2. If partial overlap,head trim the enqueued meta
   *           return;
   */

  while(next_meta && after(new_end, next_meta->end_seq))
  {
    /* Complete Overlap */
    /* Dequeue the next_meta */
    prev_meta->next_recv_meta = next_meta->next_recv_meta;
    destroy_recv_meta(next_meta);
    decr_ofoQ_len(tcp_sk);
    next_meta = prev_meta->next_recv_meta;
  }

  /* Check for partial Overlap */
  if(next_meta)
  {
    uint32 overlap = signed_diff(new_end, next_meta->start_seq);
    head_trim_recv_meta(next_meta, overlap);
  }

  return UTCP_SUCC;
}

/* This function reads the ofoQ till recvnxt
 * and dequeues the recv_meta
 * passes on the meta to app
 * Update the recvwnd
 * Update the redvnxt
 * Generate the ack immediately
 */

int inorder_data_to_app(ptcp_sk tcp_sk)
{
  while(tcp_sk->recvnxt == ofoQ_head(tcp_sk)->start_seq)
  {
    update_tcp_seqspace(tcp_sk, ofoQ_head(tcp_sk)); 
    utcp_data_to_app(tcp_sk, ofoQ_head(tcp_sk));
    remove_ofoQ_head(tcp_sk);
  }

  return UTCP_SUCC;
}


int utcp_data_enqueue(ptcp_sk tcp_sk, ptcp_recv_meta recv_meta)
{
  /* Step 1. (Fast Path) Most common case: If the received packet is expected
   * packet, just hand over the packet to application
   */

  if(tcp_sk->recvnxt == recv_meta->start_seq)
  {
    /* In order packet */
    if(available_recvwnd(tcp_sk) <= 0)
    {
      /* Packet is out of window 
       * Drop this packet */
      goto out_of_window;
    }
    /* Update the recv meta as it does not contain any retransmission etc */
    recv_meta->tcp_valid_len = recv_meta->ttl_tcp_payload;
    recv_meta->tcp_new_payload_start = recv_meta->tcppkt + recv_meta->tcp_hlen;

    update_tcp_rcvnxt(tcp_sk, recv_meta->end_seq);

    utcp_data_to_app(tcp_sk, recv_meta);
    /* we dont update the recvwnd here
     * as this data is not supposed to be buffered inside the stack
     */

    /* Check if this data formed the overlap with ofoQ */
    if(ofoQ_len(tcp_sk))
    {
      uint32 new_end = recv_meta->end_seq;
      ptcp_recv_meta next_meta = ofoQ_head(tcp_sk);
      while(next_meta && after(new_end, next_meta->end_seq))
      {
        /* Complete Overlap */
        /* Dequeue the next_meta */
        ofoQ_head(tcp_sk) = next_meta->next_recv_meta;
        remove_ofoQ_head(tcp_sk);
//        destroy_recv_meta(next_meta);

//        decr_ofoQ_len(tcp_sk);

        next_meta = ofoQ_head(tcp_sk);
      }

      /* Check for partial Overlap */
      if(next_meta)
      {
        uint32 overlap = signed_diff(new_end, next_meta->start_seq);
        head_trim_recv_meta(next_meta, overlap);
        
        /* Step 1a. Check the ofo queue if we can hand over more data to app
         * It may happen that step 1 has already filled some hole in the ofo
         * queue.
         *
         * Update the ofo queue considering the received and handed over packet
         *
         * Return if completed playing with ofo queue and current packet
         */

        inorder_data_to_app(tcp_sk);
        goto quick_ack;
      }
    }

    /* we are done with received packet */
    //return UTCP_SUCC;
    goto quick_ack;
  }

  /*Step 2: Second Most common Case: Retransmission */
  if(before(recv_meta->end_seq, tcp_sk->recvnxt))
  {
    /* We get the complete retransmitted packet
     * Need to send out an immediate ACK and drop this packet */

    /* RFC2883: Handling of duplicate SACK here if needed */
    goto quick_ack;
  }

  /* Step 3: If out of our window */

  if (!before(recv_meta->start_seq, tcp_sk->recvnxt + available_recvwnd(tcp_sk)))
  {
    /* This packet falls beyond our acceptable window */
    goto out_of_window;
  }

  /* Step 4: Out of Order Packet */

  utcp_ofo_queue(tcp_sk, recv_meta);

  goto quick_ack;

quick_ack:
  enter_quick_ack(tcp_sk);
out_of_window:
  return UTCP_SUCC;
}

static inline void utcp_update_sndwl(ptcp_sk tcp_sk, uint32 seq)
{
  tcp_sk->snd_wl1 = seq;
}

/* utcp_can_update_window
   Update the window if either
   1. this segments ACK is greater than snduna
   2. this segment SEQ is greater than last time when window was updated
   3. this segment ACK is Eq to last time when window was updated and the new window is greater than current send window
 */

static inline int utcp_can_update_window(ptcp_sk tcp_sk, uint32 seg_ack, uint32 seg_seq, uint32 nwin)
{
  return  after(seg_ack, tcp_sk->snduna) ||
    after(seg_seq, tcp_sk->snd_wl1) ||
    (seg_seq == tcp_sk->snd_wl1 && nwin > tcp_sk->sndwnd);
}

static inline uint32 utcp_update_window(ptcp_sk tcp_sk, ptcp_recv_meta recv_meta, uint32 seg_ack, uint32 seg_seq)
{
  uint32 nwin = ntohs(tcp_hdr(recv_meta)->window);
  uint32 flag;

  if(likely((!recv_meta->syn)))
    nwin <<= tcp_sk->rcv_wscale;

  if(utcp_can_update_window(tcp_sk, seg_ack, seg_seq, nwin))
  {
    flag |= FLAG_ACK_WND_UPD;

    utcp_update_sndwl(tcp_sk, seg_seq);

    if(likely(tcp_sk->sndwnd != nwin))
    {
      tcp_sk->sndwnd = nwin;
    }
  }

  return flag;
}

/* This function takes the ack packet
   Tries to purge the retransmit queue till the sndnxt from snduna
   updates the snduna
   seg_ack is the ack number of this segment
 */
static uint32 utcp_clean_retx_queue(ptcp_sk tcp_sk, uint32 seg_ack)
{
  psendQ_node psnduna = tcp_sk->psnduna;
  psendQ_node psndnxt = tcp_sk->psndnxt;
  uint32 flag=0;
  uint32 seq_time=0;
  uint32 accumulated_acked_bytes = 0;

  while(psnduna && (psnduna != psndnxt))
  {
    ptcp_pkt_meta tcp_meta = ref_tcp_meta(psnduna);
    if(seg_ack < end_seq_of_tcp_meta(tcp_meta))
    {
      /* XXX: We dont support the partial ACKs */
      break;
    }
    printf("STACK: ACK = %u Start Seq of Meta = %u and End Seq of Meta = %u\n", seg_ack, tcp_meta->start_seq, end_seq_of_tcp_meta(tcp_meta));
    accumulated_acked_bytes += tcp_meta->tcp_payload;
    /* Step 1. Update RTT */
    if (!is_seg_retx(tcp_meta)) {
        if (!seq_time) {
            seq_time = tcp_meta->sent_time;
        }
        flag |= FLAG_ACK_DATA_ACKED;
        printf("STACK: Data Acked Seg\n");
    } else {
      flag |= FLAG_ACK_RETR_SEG;
      printf("STACK: ACK to RETX Seg\n");
    }
    /* Gather the next ptr as current node will be
     * deallocated by utcp_remove_sendQ() */
    psnduna =  next_node(psnduna);
    /* Step 2. Remove from SendQ */
    utcp_remove_sendQ(tcp_sk, tcp_meta);

    /* Step 3. Deallocate the tcp meta */
    dealloc_tcp_meta(tcp_meta);
    /* tcp_meta is not accessible after this call */
  }

  leave_peer_flow_control(tcp_sk, accumulated_acked_bytes);
  /* update snduna */
  update_snduna(tcp_sk, psnduna, accumulated_acked_bytes);
  /* Update RTT if this ACK is not to a retransmitted packet */
  if((flag & FLAG_ACK_DATA_ACKED))
  {
    utcp_update_rtt_no_ts(tcp_sk, seq_time);
  }
  return flag;
}

static void utcp_may_send_wndupd(ptcp_sk tcp_sk, int bytes_acked)
{
    int old_wnd = tcp_sk->advwnd;
    if(old_wnd < tcp_sk->max_recvQ_size)
        tcp_sk->advwnd += bytes_acked;
    if(tcp_sk->advwnd > tcp_sk->max_recvQ_size)
        tcp_sk->advwnd = tcp_sk->max_recvQ_size;

    /* Receiver Silly Window Syndrome avoided
     * Send the window update only if our buffer
     * has more than half of adv size
     */
    if((old_wnd != tcp_sk->advwnd) && (tcp_sk->advwnd >= (tcp_sk->max_recvQ_size>>1)))
    {
        utcp_snd_ack(tcp_sk);
    }

}


static inline utcp_may_fast_retransmit(ptcp_sk tcp_sk)
{
}

static inline int is_sndwnd_usable(ptcp_sk tcp_sk)
{
  return (tcp_sk->sndwnd >=  len_of_sndnxt(tcp_sk));
}

static void utcp_start_probe_timer(ptcp_sk tcp_sk)
{
/* XXX: Revisit the probe timer */
}

static void utcp_probe_timer_expiry(ptcp_sk tcp_sk)
{
/* XXX: Revisit the probe timer */
}

static void utcp_stop_probe_timer(ptcp_sk tcp_sk)
{
/* XXX: Revisit the probe timer */

}

static void utcp_restart_probe_timer(ptcp_sk tcp_sk)
{
/* XXX: Revisit the probe timer */
}

static void utcp_ack_probe(ptcp_sk tcp_sk)
{
  /* If the window is open significantly because of incoming ACK
     1. Stop the probe timer
     else
     2. Restart the probe timer
   */

   if(is_sndwnd_usable(tcp_sk))
   {
     utcp_stop_probe_timer(tcp_sk);
   }
   else
   {
     utcp_restart_probe_timer(tcp_sk);
   }
}

int utcp_ack(ptcp_sk tcp_sk, ptcp_recv_meta recv_meta, uint32 flag)
{
  uint32 old_snduna = tcp_sk->snduna;
  uint32 old_sndnxt = tcp_sk->sndnxt;
  uint32 seg_ack = recv_meta->seg_ack;
  uint32 seg_seq = recv_meta->start_seq;
  int bytes_acked;

  /* Validity check for the ack */
  if(before(seg_ack, old_snduna))
    goto old_ack;

  if(after(seg_ack, old_sndnxt))
    goto invalid_ack;

  if(after(seg_ack, old_snduna))
    flag |= FLAG_ACK_SND_UNA_ADV;

  if(seg_contains_data(recv_meta))
    flag |= FLAG_ACK_DATA;

  /* XXX: If segment ACKs SYN check is remainigng */

  flag |= utcp_update_window(tcp_sk, recv_meta, seg_ack, seg_seq);

  flag |= utcp_clean_retx_queue(tcp_sk, seg_ack);

  bytes_acked = tcp_sk->snduna - old_snduna;
  printf("STACK: ACK: Bytes acked = %u New snduna = %u New Sndua = %u flag = %x\n", bytes_acked, tcp_sk->snduna, old_snduna, flag);

  if(flag & FLAG_DUP_ACK)
    utcp_may_fast_retransmit(tcp_sk);

  if(bytes_acked && !(flag & FLAG_ACK_RETR_SEG))
    utcp_cong_avoid(tcp_sk, bytes_acked);

  if((flag & FLAG_ACK_WND_UPD) && (len_of_sndnxt(tcp_sk)))
    utcp_ack_probe(tcp_sk);
      
old_ack:
  return UTCP_SUCC;
invalid_ack:
        assert(0);
  return UTCP_ERR;
}

static inline ptcp_pkt_meta create_tcp_meta_nodata(ptcp_sk tcp_sk, int flags)
{
  ptcp_pkt_meta meta;
  create_tcp_meta_from_buff(tcp_sk, NULL, 0, &meta, flags);
  return (meta);
}

/* utcp_snd_ack
   This function creates the ack packet and tries to send on the network
*/

static void utcp_snd_ack(ptcp_sk tcp_sk)
{
  ptcp_pkt_meta tcp_meta;
  tcp_meta = create_tcp_meta_nodata(tcp_sk, UTCP_FLAG_ACK);

  if(unlikely((!tcp_meta)))
    return;

  utcp_send_one_pkt(tcp_sk, tcp_meta);

  dealloc_tcp_meta(tcp_meta);
}

static inline void utcp_snd_ack_check(ptcp_sk tcp_sk)
{
  if(is_quick_ack(tcp_sk))
  {
    leave_quick_ack(tcp_sk);
   /* Do we need send the ack immediately?? */
    utcp_snd_ack(tcp_sk);
  }
  /* XXX: Delay ACK generation code here */
}

int utcp_recv_establish(ptcp_sk tcp_sk, ptcp_recv_meta recv_meta)
{
  int ret, flag = 0;
  /* Step 1. Process the ACK number */
  ret = utcp_ack(tcp_sk, recv_meta, flag);

  if(ret == UTCP_ERR)
  {
        assert(0);
    goto _drop;
  }

  /* Step 2. Process the Seq space */
  if(seg_contains_data(recv_meta))
      ret = utcp_data_enqueue(tcp_sk, recv_meta);

  /* Step 3. Can We send further data?? */
  ret = utcp_try_send(tcp_sk);

  /* Step 4. Send ACK if required */
  if(!ret)
  {
    /* ret zero means try_send sent nothing out
       otherwise that would have resulted in sending the ACK out - piggy-backed
     */

    utcp_snd_ack_check(tcp_sk);
  }
  leave_quick_ack(tcp_sk);

  return UTCP_SUCC;

_drop:
  return ret;
}

/* TCP SK Creation , Destroy, Init Functions */

static inline ptcp_sk alloc_tcp_sk()
{
  ptcp_sk tcp_sk = (ptcp_sk)malloc(sizeof(ttcp_sk));
  if(unlikely(!tcp_sk))
    return NULL;

  memset(tcp_sk, 0, sizeof(ttcp_sk));

  return tcp_sk;
}

static inline void free_tcp_sk(ptcp_sk tcp_sk)
{
  free(tcp_sk);
}

void inline init_tcp_sk_cong_opts(ptcp_sk tcp_sk)
{
  init_reno_opts(tcp_sk);
}

void inline init_ip_sk_opts(ptcp_sk tcp_sk)
{
  tcp_sk->ip_sk.ttl = UTCP_DEF_TTL;
  tcp_sk->ip_sk.id = UTCP_DEF_ID;
}

void init_tcp_sk_opts(ptcp_sk tcp_sk)
{
  tcp_sk->mss = UTCP_MAX_SEG;
  tcp_sk->snd_wscale = UTCP_DEF_WSCALE;
  tcp_sk->rcv_wscale = UTCP_DEF_WSCALE;

  tcp_sk->rto = UTCP_DEF_RTO;
  tcp_sk->max_retries = UTCP_MAX_RETRIES;

  tcp_sk->max_sendQ_size = UTCP_MAX_SENDQ;
  tcp_sk->advwnd = tcp_sk->max_recvQ_size = UTCP_MAX_RECVQ_BYTES;
}

void inline init_tcp_sk(ptcp_sk tcp_sk)
{
  init_ip_sk_opts(tcp_sk);
  init_tcp_sk_opts(tcp_sk);
  init_tcp_sk_cong_opts(tcp_sk);
}

static inline void utcp_bind_tcp_sk(ptcp_sk tcp_sk, uint32 localaddr, uint32 remoteaddr, uint16 localport, uint16 remoteport)
{
  tcp_sk->tcpsrcport = localport;
  tcp_sk->tcpdstport = remoteport;
  tcp_sk->ipsrcaddr = localaddr;
  tcp_sk->ipdstaddr = remoteaddr;
  init_recycle_hdr(tcp_sk, &tcp_sk->recycle_hdr);
}

ptcp_sk create_tcp_sk(uint32 localaddr, uint32 remoteaddr, uint16 localport, uint16 remoteport)
{
  ptcp_sk tcp_sk = alloc_tcp_sk();

  if(unlikely(!tcp_sk))
    return NULL;

  init_tcp_sk(tcp_sk);
  utcp_bind_tcp_sk(tcp_sk, localaddr, remoteaddr, localport, remoteport);

  return tcp_sk;
}



void delloc_tcp_sk(ptcp_sk tcp_sk)
{
  purge_sendQ(tcp_sk);
  purge_recvQ(tcp_sk);
  utcp_stop_probe_timer(tcp_sk);

  free(tcp_sk);
}

/* Stub integration related function */

int utcp_incoming_packet(uint8* ippkt, uint16 len, ptcp_sk tcp_sk)
{
  ptcp_recv_meta recv_meta; 

  int ret;
  /* Basic IP packet Checks */

  /* TCP packet Creation */
  if(unlikely((!(recv_meta = alloc_recv_meta(tcp_sk)))))
    return UTCP_ERR;

  if(unlikely(utcp_incoming_ip_pkt(tcp_sk, recv_meta, ippkt, len) < 0))
  {
    destroy_recv_meta(recv_meta);
    return UTCP_ERR;
  }

  /* TCP Packet Parsing */
  if(unlikely((utcp_incoming_tcp_pkt(tcp_sk, recv_meta)<0)))
  {
    destroy_recv_meta(recv_meta);
    return UTCP_ERR;
  }
}

static inline int is_destined_to_us(ptcp_sk tcp_sk, struct iphdr *iphdr)
{
  return (tcp_sk->ipsrcaddr == ntohl(iphdr->daddr) && (tcp_sk->ipdstaddr == ntohl(iphdr->saddr)));
}

static inline void fill_ip_recv_meta(ptcp_recv_meta recv_meta, struct iphdr *iph)
{
  recv_meta->ip_hlen = IP_HLEN(iph);
}

static inline int ip_basic_checks(ptcp_recv_meta recv_meta, uint8* ippkt, uint16 len)
{
  struct iphdr *iph = (struct iphdr *)ippkt;
  uint16 recv_len = len;

  uint16 ip_ttllen = ntohs(iph->tot_len);
  uint8 ip_hlen = IP_HLEN(iph);

  /* IPv6 not supported */
  if(unlikely(iph->version != IPv4))
    return UTCP_ERR;
  
  if(unlikely(((ip_hlen < MIN_IPv4_HLEN) || (ip_hlen > MAX_IPv4_HLEN))))
    return UTCP_ERR;

  if(unlikely((ip_ttllen != recv_len)))
    return UTCP_ERR;

  /* Fragmentation , Reassembly not supported */
  if(unlikely((IP_MORE_FRAG(iph)||(IP_FRAG_OFF(iph)))))
    return UTCP_ERR;

  /* nonTCP not supported */
  if(unlikely(iph->protocol != IPPROTO_TCP))
    return UTCP_ERR;

#if UTCP_INCOMING_IP_CSUM
  /* Verify IP Checksum here */
#endif

  if(unlikely((is_destined_to_us(recv_meta->tcp_sk, iph) == 0)))
    return UTCP_ERR;

  alloc_ip_pkt_recv_meta(recv_meta, ippkt, recv_len);
  
  /* Update IP related basic information */
  fill_ip_recv_meta(recv_meta, iph);

  return UTCP_SUCC;
}

int utcp_incoming_ip_pkt(ptcp_sk tcp_sk, ptcp_recv_meta recv_meta, uint8* ippkt, uint16 len)
{
  if(unlikely(ip_basic_checks(recv_meta, ippkt, len)<0))
    return UTCP_ERR;

  return UTCP_SUCC;
}

static inline int is_tcp_destined_to_us(ptcp_sk tcp_sk, struct tcphdr *tcph)
{
  return (tcp_sk->tcpsrcport == ntohs(tcph->dest) && (tcp_sk->tcpdstport == ntohs(tcph->source)));
}

static inline void fill_tcp_recv_meta(ptcp_recv_meta recv_meta, struct tcphdr *tcphdr)
{
  recv_meta->tcppkt = (recv_meta->pkt + recv_meta->ip_hlen);
  recv_meta->tcp_hlen = TCP_HLEN(tcphdr);
  recv_meta->ttl_tcp_payload = recv_meta->iplen - recv_meta->ip_hlen - recv_meta->tcp_hlen;

  recv_meta->cwr = tcphdr->cwr;
  recv_meta->ece = tcphdr->ece;
  recv_meta->urg = tcphdr->urg;
  recv_meta->ack = tcphdr->ack;
  recv_meta->psh = tcphdr->psh;
  recv_meta->rst = tcphdr->rst;
  recv_meta->syn = tcphdr->syn;
  recv_meta->fin = tcphdr->fin;

  recv_meta->start_seq = ntohl(tcphdr->seq);
  recv_meta->end_seq = recv_meta->start_seq + recv_meta->ttl_tcp_payload;
  recv_meta->seg_ack = ntohl(tcphdr->ack_seq);
}


static int tcp_basic_checks(ptcp_recv_meta recv_meta)
{
  struct iphdr *iph = (struct iphdr *)recv_meta->pkt;
  uint16 ip_len = recv_meta->iplen;
  uint8 ip_hlen = recv_meta->ip_hlen;

  struct tcphdr *tcphdr = (struct tcphdr *)(recv_meta->pkt + ip_hlen);
  uint8 tcp_hlen = TCP_HLEN(tcphdr);
  int tcp_payload_len = ip_len - ip_hlen - tcp_hlen;

  /* Basic Checks for TCP header len */
  if(unlikely( (((tcp_hlen < MIN_TCP_HDR_LEN) || (tcp_hlen > MAX_TCP_HDR_LEN)) ||
               (tcp_payload_len < 0))
               )
              )
    return UTCP_ERR;

  /* Update the recv meta with TCP header info */

#if UTCP_INCOMING_TCP_CSUM
  /* XXX: Verify TCP check sum here */
#endif

  if(unlikely( (is_tcp_destined_to_us(recv_meta->tcp_sk, tcphdr) == 0) ))
    return UTCP_ERR;

  fill_tcp_recv_meta(recv_meta, tcphdr);

  return UTCP_SUCC;
}

/* utcp_incoming_tcp_pkt
Entry point to TCP layer parsing
Validates the TCP mandatory header
Calls the state machine
And further packet processing

Assumption:
IP packet is validated/reassembled
Recv_meta->ippkt contains the start of the ip hdr
*/

int utcp_incoming_tcp_pkt(ptcp_sk tcp_sk, ptcp_recv_meta recv_meta)
{
  /* Step 1. Validate the Mandatory header */

  if(unlikely((tcp_basic_checks(recv_meta)<0)))
    return UTCP_ERR;

  /* Step 2. Validate / Parse the Optional Header */
  /* XXX: Revisit Optional Header */

  /* Step 3. State Machine ??? */
  /* XXX: Revisit state machine */

  /* Step 4. Establish State Handling */
  utcp_recv_establish(tcp_sk, recv_meta);
}

int utcp_migrate_socket(ptcp_sk tcp_sk, pmig_info mig_info)
{
  tcp_sk->isn = tcp_sk->sndnxt = tcp_sk->snduna = mig_info->snduna;
  tcp_sk->recvnxt = mig_info->recvnxt;
  tcp_sk->snd_wscale = mig_info->snd_wscale;
  tcp_sk->rcv_wscale = mig_info->rcv_wscale;
  tcp_sk->mss = mig_info->mss;
  /* XXX: Revisit */
  tcp_sk->sndwnd = UTCP_MAX_SENDQ_BYTES << tcp_sk->snd_wscale;
}

void utcp_register_data_to_app(ptcp_sk tcp_sk, void (*data_to_app)(void *tcp_sk, uint8* data, uint16 len, void *pktuserptr, void *data_to_app_ptr, void *peer_ptr), void *userptr)
{
  tcp_sk->cb.data_to_app = data_to_app;
  tcp_sk->cb.data_app_ptr = userptr;
}
void utcp_register_packet_out(ptcp_sk tcp_sk, void (*packet_out)(void *tcp_sk, uint8* ippkt, uint16 len, void* packet_out_ptr, void* user_peer_ptr), void* userptr)
{
  tcp_sk->cb.packet_out = packet_out;
  tcp_sk->cb.packet_out_ptr = userptr;
}

void utcp_bind_peer_socks(ptcp_sk tcp_sk1, void *userptr1, ptcp_sk tcp_sk2,void *userptr2, peer_binding_t binding)
{
  tcp_sk1->peer_sk.tcp_sk = (void *)tcp_sk2;
  tcp_sk1->peer_sk.user_peer_ptr = userptr2;

  tcp_sk2->peer_sk.tcp_sk = (void *)tcp_sk1;
  tcp_sk2->peer_sk.user_peer_ptr = userptr1;

  tcp_sk1->peer_sk.binding = tcp_sk2->peer_sk.binding = binding;
}

void utcp_unbind_peer_socks(ptcp_sk tcp_sk)
{
  ptcp_sk peer_sk;
  peer_sk = tcp_sk->peer_sk.tcp_sk;

  tcp_sk->peer_sk.tcp_sk = NULL;
  tcp_sk->peer_sk.user_peer_ptr = NULL;
  tcp_sk->peer_sk.binding = 0;

  peer_sk->peer_sk.tcp_sk = NULL;
  peer_sk->peer_sk.user_peer_ptr = NULL;
  peer_sk->peer_sk.binding = 0;
}
