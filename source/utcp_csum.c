#include "utcp_csum.h"

/*

To calculate TCP checksum a "pseudo header" is added to the TCP header. This includes:

IP Source Address   4 bytes
IP Destination Address    4 bytes
TCP Protocol      2 bytes
TCP Length        2 bytes

The checksum is calculated over all the octets of the pseudo header, TCP header and data. 
If the data contains an odd number of octets a pad, zero octet is added to the end of data. The pseudo 
header and the pad are not transmitted with the packet. 

In the example code, 
u16 buff[] is an array containing all the octets in the TCP header and data.
u16 len_tcp is the length (number of octets) of the TCP header and data.
BOOL padding is 1 if data has an even number of octets and 0 for an odd number. 
u16 src_addr[4] and u16 dest_addr[4] are the IP source and destination address octets.

**************************************************************************
Function: tcp_sum_calc()
**************************************************************************
Description: 
  Calculate TCP checksum

Taken from: http://www.netfor2.com/tcpsum.htm
***************************************************************************
*/

uint16 tcp_sum_calc(uint16 len_tcp, uint16 src_addr[],uint16 dest_addr[], int padding, uint16 buff[])
{
  uint16 prot_tcp=6;
  uint16 padd=0;
  uint16 word16, i;
  uint32 sum;  

  // Find out if the length of data is even or odd number. If odd,
  // add a padding byte = 0 at the end of packet
  if (padding){
    padd=1;
    buff[len_tcp]=0;
  }

  //initialize sum to zero
  sum=0;

  // make 16 bit words out of every two adjacent 8 bit words and 
  // calculate the sum of all 16 vit words
  for (i=0;i<len_tcp+padd;i=i+2){
    word16 =((buff[i]<<8)&0xFF00)+(buff[i+1]&0xFF);
    sum += (unsigned long)word16;
  } 
  // add the TCP pseudo header which contains:
  // the IP source and destinationn addresses,
  for (i=0;i<4;i=i+2){
    word16 =((src_addr[i]<<8)&0xFF00)+(src_addr[i+1]&0xFF);
    sum += word16; 
  }
  for (i=0;i<4;i=i+2){
    word16 =((dest_addr[i]<<8)&0xFF00)+(dest_addr[i+1]&0xFF);
    sum +=word16;   
  }
  // the protocol number and the length of the TCP packet
  sum += (prot_tcp + len_tcp);

  // keep only the last 16 bits of the 32 bit calculated sum and add the carries
  while (sum>>16)
    sum = (sum & 0xFFFF)+(sum >> 16);

  // Take the one's complement of sum
  return ((unsigned short) (~sum));
}

/*

The IP Header Checksum is computed on the header fields only. 
Before starting the calculation, the checksum fields (octets 11 and 12) 
are made equal to zero. 

In the example code, 
u16 buff[] is an array containing all octets in the header with octets 11 and 12 equal to zero. 
u16 len_ip_header is the length (number of octets) of the header.

**************************************************************************
Function: ip_sum_calc
Description: Calculate the 16 bit IP sum.

Taken from: http://www.netfor2.com/ipsum.htm
***************************************************************************
*/

uint16 ip_sum_calc(uint16 len_ip_header, uint16 buff[])
{
  uint16 word16;
  uint32 sum=0;
  uint16 i;

  // make 16 bit words out of every two adjacent 8 bit words in the packet
  // and add them up
  for (i=0;i<len_ip_header;i=i+2){
    word16 =((buff[i]<<8)&0xFF00)+(buff[i+1]&0xFF);
    sum += (uint32) word16; 
  }

  // take only 16 bits out of the 32 bit sum and add up the carries
  while (sum>>16)
    sum = (sum & 0xFFFF)+(sum >> 16);

  // one's complement the result
  return ((uint16) (~sum));
}


/************** Code By Yogesh ****************************/


unsigned short cal_cksum(unsigned short len, unsigned short *buff, unsigned int sum)
{
    /* add each 16 bit word */
    for (;len > 0; len--){
        sum = sum + *buff++;
    }
    /* take only 16 bits out of the 32 bit sum and add up the carries */
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    /* one's complement the result */
    return ((unsigned short) ~sum);
}

unsigned short ip_csum(unsigned short *ip_dgram, unsigned int hdr_len)
{
    return cal_cksum(hdr_len, (unsigned short *)ip_dgram, 0);
}


unsigned short tcp_csum(unsigned int src, unsigned int dst,unsigned short *tcp_seg, unsigned int tcp_len)
{
    unsigned int sum = 0;
    sum = (src & 0x0000FFFF) + (src >> 16) +(dst & 0x0000FFFF) + (dst >> 16) + (0x0600) + (htons(tcp_len));

    return cal_cksum(tcp_len, (unsigned short *)tcp_seg, sum);
}


/******************** Code by Randhir *********************/
unsigned short tcp_checksum(struct iphdr * ip, struct tcphdr * tcp) 
{
    register unsigned int   sum = 0;
    unsigned short            total_len = ntohs(ip->tot_len);
    unsigned int            count = total_len - (ip->ihl*4);
    unsigned short            *addr = (unsigned short*)tcp;
    pseudo_header       pseudohead = { 0};
    unsigned short            *psuedo_hdr = (unsigned short*)(&pseudohead);
    unsigned int            len = sizeof(pseudohead);

    pseudohead.src_addr=ip->saddr;
    pseudohead.dst_addr=ip->daddr;
    pseudohead.zero=0;
    pseudohead.proto=IPPROTO_TCP;
    pseudohead.length=htons(count);

    /* handle pseudo-header first */
    while (len > 0)
    {
        sum += *psuedo_hdr++;
        len -= 2;
    }

    /* now the tcp block */
    while( count > 1 )  {
        sum += * addr++;
        count -= 2;
    }

    if( count > 0 )
        sum += * (uint8_t *) addr;

    while (sum>>16)
        sum = (sum & 0xffff) + (sum >> 16);

    return (~sum & 0xffff);
}

unsigned short ip_checksum(struct iphdr * ip) 
{
    register unsigned int   sum = 0;
    unsigned int            count = (ip->ihl*4);
    unsigned short          *addr = (unsigned short*)ip;


    while( count > 1 )  {
        sum += * addr++;
        count -= 2;
    }

    if( count > 0 )
        sum += * (uint8_t *) addr;

    while (sum>>16)
        sum = (sum & 0xffff) + (sum >> 16);

    return (~sum & 0xffff);
}
