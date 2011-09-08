#ifndef __UTCP_ERR_H__
#define __UTCP_ERR_H__

enum utcp_err
{
  UTCP_SEND_FULL = -2,
  UTCP_ERR = -1,
  UTCP_SUCC = 0
};

typedef enum utcp_err utcp_err_t;

#endif
