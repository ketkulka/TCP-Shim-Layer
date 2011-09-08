#include "utcpio.h"
#include "utcp.h"


int  utcp_device_send(ptcp_sk tcp_sk, ptcp_pkt_meta tcp_meta, uint8 *pkt, uint16 pkt_len)
{
  tcp_sk->cb.packet_out(tcp_sk, pkt, pkt_len, tcp_sk->cb.packet_out_ptr, tcp_sk->peer_sk.user_peer_ptr);
  return UTCP_SUCC;
}
