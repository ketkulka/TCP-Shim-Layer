#ifndef __UTCPIO_H__
#define __UTCPIO_H__
#include "utype.h"
#include "utcp.h"


int  utcp_device_send(ptcp_sk, ptcp_pkt_meta, uint8 *pkt, uint16 pkt_len);

#endif
