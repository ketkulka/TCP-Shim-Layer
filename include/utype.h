#ifndef __UTYPE_H__
#define __UTYPE_H__


typedef unsigned int uint32;
typedef unsigned long long uhyper;
typedef signed int int32;
typedef unsigned short uint16;
typedef signed short int16;
typedef unsigned char uchar;
typedef unsigned char uint8;

#define TRUE 1
#define FALSE  0

#define SRC 0
#define DST 1

#define MIN(a,b) (a<b?a:b)
#define MAX(a,b) (a>b?a:b)
#define EQUAL(a,b) (a==b)

#define likely(x)   __builtin_expect((x),1)
#define unlikely(x) __builtin_expect((x),0)


static inline int before(uint32 seq1, uint32 seq2)
{
  return (int)(seq1-seq2) < 0;
}

static inline int signed_diff(uint32 seq1, uint32 seq2)
{
  return (int)(seq1-seq2);
}

#define after(a,b) before(b,a)

#endif
