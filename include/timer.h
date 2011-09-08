#ifndef __TIMER_H__
#define __TIMER_H__

#include "utype.h"
#include "list.h"

/* all timer values are in milliseconds */
#define TIMER_INTERVAL 20
#define TIMER_GRANUL TIMER_INTERVAL
#define MAX_TIME_VALUE 25000

/* wheel len = 25000/20 */
#define WHEEL_LEN 1250

//#define TIMER_DEBUG 

#define TWHEEL_LIST(slot) (&(twheel.timerwheel[slot]))

enum t_type
{
  ONE_SHOT,
  CONTINUOUS
};
typedef enum t_type timer_type;

struct timerinfo
{
  uint8  isrunning;
  uint16 slot;
  uint16 timeout;
  timer_type type;
  void *userptr;
  void (*expiry_handler)(void *userptr);
};

typedef struct timerinfo ttimerinfo;
typedef struct timerinfo* ptimerinfo;

typedef struct dll timer_wheel;
typedef struct dll_node *ptimerinfo_node;

struct mytimer
{
  uint32 time; //may be required in future
  uint32 rollover; //may be required in future
  uint8 timer_running;
  uint16 curr_slot;
  timer_wheel timerwheel[WHEEL_LEN];
};

struct mytimer twheel;

typedef struct mytimer *ptimerwheel;

/* Exported APIs */
int start_timer();
int stop_timer();
void *add_one_shot_timer(void (*expiry_handler)(void *userptr), void *userptr, uint16 timeout);
void *add_repetitive_timer(void (*expiry_handler)(void *userptr), void *userptr, uint16 timeout);
int remove_timer(void *timerinfo);
int modify_timer_val(void *tinfo, uint16 newtimeout);
int restart_timer(void *tinfo);

void execute_timerwheel(struct dll *timer_list);

#define time_now twheel.time

#endif
