#include "timer.h"
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <sys/time.h>
#include <assert.h>
    
#define GET_RIGHT_SLOT(timeout) ((MAX((timeout/TIMER_INTERVAL), 1)+twheel.curr_slot)%WHEEL_LEN)

/* Declarations first */
static int check_timer_expiry();

void execute_timerwheel(struct dll *timer_list);

static void stop_timer_list(struct dll *timer_list);

static void add_timer_node(ptimerinfo_node timerinfo_node, ptimerinfo timerinfo);

/* Static Inline Functions First */
void static inline free_timer_info(ptimerinfo timerinfo)
{
  free(timerinfo);
}

static inline ptimerinfo ref_timer_info(ptimerinfo_node node)
{
  return(node?node->data:NULL);
}

static inline init_timer_wheel()
{
  memset(&twheel, 0, sizeof(twheel));
}

ptimerinfo static inline get_timer_info()
{
  return malloc(sizeof(ttimerinfo));
  /* if needed in future 
  ptimerinfo tinfo = malloc(sizeof(ttimerinfo));
  if(unlikely(!tinfo))
  {
    return NULL;
  }
  memset(tinfo, 0, sizeof(ttimerinfo));
  return tinfo;
  */
}

static inline ptimerinfo_node get_timer_head(struct dll *timer_list)
{
  return timer_list->head;
}

static inline ptimerinfo_node get_next_timer_node(ptimerinfo_node node)
{
  return node->next;
}


static inline ptimerinfo_node insert_timerinfo(ptimerinfo timerinfo, struct dll *pdll)
{
  return dll_insert_at_tail(pdll, timerinfo);
}

static inline void insert_timerinfo_node(ptimerinfo_node node, struct dll *pdll)
{
  dll_link_at_tail(pdll, node);
}

static inline int remove_timerinfo(ptimerinfo_node node, struct dll *pdll)
{
  assert(pdll->len);
  ptimerinfo timerinfo = ref_timer_info(node);
    
  if(unlikely(dll_delete_node(pdll, node) < 0))
  {
      assert(0);
    return -1;
  }

  timerinfo->isrunning = FALSE;
  return 0;
}

static inline int dequeue_timerinfo(ptimerinfo_node node, struct dll *pdll)
{
  assert(pdll->len);
  ptimerinfo timerinfo = ref_timer_info(node);
    
  if(unlikely(dll_unlink(pdll, node)<0))
  {
    return -1;
  }

  timerinfo->isrunning = FALSE;
  return 0;
}

static inline int _do_restart_timer(ptimerinfo_node timerinfo_node, ptimerinfo timerinfo)
{
  if(dequeue_timerinfo(timerinfo_node, TWHEEL_LIST(timerinfo->slot)) < 0)
  {
    return -1;
  }

  add_timer_node(timerinfo_node, timerinfo);

  return 0;
}

static inline ptimerinfo_node _do_add_timer(ptimerinfo timerinfo)
{

  /* Calculate the next time slot */
  timerinfo->slot = GET_RIGHT_SLOT(timerinfo->timeout);

  ptimerinfo_node timerinfo_node = insert_timerinfo(timerinfo, TWHEEL_LIST(timerinfo->slot));
  
  timerinfo->isrunning = TRUE;

  return timerinfo_node;
}


static inline void stop_all_pending_timers()
{
  uint16 curr_slot = 0;

  while(curr_slot < WHEEL_LEN)
  {
    stop_timer_list(TWHEEL_LIST(curr_slot));
    curr_slot++;
  }
}

void execute_timerwheel(struct dll *timer_list)
{
  /* Return Quickly from the obvious case */
  if((!timer_list) || (!timer_list->len))
  {
    return;
  }
  ptimerinfo_node curr_node, next_node;
  ptimerinfo curr_timer_info, next_timer_info;

  curr_node = get_timer_head(timer_list);

  curr_timer_info = ref_timer_info(curr_node);

  while(curr_node && curr_timer_info)
  {
    /* First reference out the next nodes
     * It may happen that the expiry handler can delete/modify the timer
     */
    next_node = get_next_timer_node(curr_node);
    next_timer_info = ref_timer_info(next_node);

    /* Handle the CONTINUOUS timers case */
    if(unlikely(curr_timer_info->type == CONTINUOUS))
    {
      if(_do_restart_timer(curr_node, curr_timer_info) < 0)
      {
        /* restart failed */
        assert(0);
      }
    }

    if(likely((curr_timer_info->expiry_handler != NULL)))
    {
      curr_timer_info->expiry_handler(curr_timer_info->userptr);
    }
    /* Do not refer curr_timer_info after calling expiry handler 
     * The expiry handler can very well remove or modify the
     * curr_timer_info */
    
    curr_node = next_node;
    curr_timer_info = next_timer_info;
  }

  return;
}

void timer_handler(int cause, siginfo_t *HowCome, void *ucontext) 
{
  /* For future working */
   uint32 oldtime = twheel.time;
   
   twheel.time += TIMER_INTERVAL;
   if(twheel.time < oldtime)
   {
     twheel.rollover ++;
   }
   
#ifdef TIMER_DEBUG
  if(!(twheel.time%1000))
     printf("Twheel Time: %u Rollover %u Slot %u\n", twheel.time, twheel.rollover, twheel.curr_slot);
#endif
  twheel.curr_slot = (++twheel.curr_slot)%WHEEL_LEN;
  
  //execute_timerwheel(TWHEEL_LIST(twheel.curr_slot));
}

static int register_timer()
{
  struct itimerval itimer;

  /* Install our SIGALRM signal handler */
  struct sigaction sa;

  sa.sa_sigaction = timer_handler;
  sigemptyset( &sa.sa_mask );
  sa.sa_flags = SA_SIGINFO; /* we want a siginfo_t */
  if (sigaction (SIGALRM, &sa, 0)) {
    perror("sigaction");
    return -1; 
  }

  /* Request SIGPROF */
  itimer.it_interval.tv_sec=0;
  itimer.it_interval.tv_usec=TIMER_INTERVAL*1000;
  itimer.it_value.tv_sec=0;
  itimer.it_value.tv_usec=TIMER_INTERVAL*1000;
  setitimer(ITIMER_REAL, &itimer, NULL);

  return(0);
}

static int deregister_timer()
{
  struct itimerval itimer;

  /* Stop Generation of SIGALRM */
  itimer.it_interval.tv_sec=0;
  itimer.it_interval.tv_usec=0;
  itimer.it_value.tv_sec=0;
  itimer.it_value.tv_usec=0;
  setitimer(ITIMER_REAL, &itimer, NULL);


  /* Install the default action on SIGALRM */
  struct sigaction sa;
  
  sa.sa_handler = SIG_DFL;
  //sigemptyset( &sa.sa_mask ); /* not needed when deregistering */
  //sa.sa_flags = SA_SIGINFO; /* we want a siginfo_t */
  if (sigaction (SIGALRM, &sa, 0)) {
    perror("sigaction");
    return -1; 
  }

}

int start_timer()
{
  if(unlikely(twheel.timer_running))
  {
    return -1;
  }

  init_timer_wheel();

  if(unlikely(register_timer() < 0))
  {
    return -1;
  }

  twheel.timer_running = TRUE;

  return 0;
}


int stop_timer()
{
  if(unlikely(twheel.timer_running == FALSE))
  {
    return -1;
  }
  /* Deregister timer should be called first
   * We should not get the timer interrupt when we are
   * processing in the timer context itself
   */
  deregister_timer();

  stop_all_pending_timers();

  init_timer_wheel();

  return 0;
}



/* add_timer 
 * This function takes 
 * 1. expiry handler func ptr
 * 2. userptr to pass to expiry_handler
 * 3. timeout
 * 
 * A. Creates the timerinfo
 * B. populate the timerinfo
 * C. Insert the timerinfo in the appropriate slot depending on timeout
 * D. return the ptimerinfo_node to the caller of the func
 *
 * NULL if failure;
 */

void add_timer_node(ptimerinfo_node timerinfo_node, ptimerinfo timerinfo)
{
  /* Calculate the next time slot */
  timerinfo->slot = GET_RIGHT_SLOT(timerinfo->timeout);

  insert_timerinfo_node(timerinfo_node, TWHEEL_LIST(timerinfo->slot));
  
  timerinfo->isrunning = TRUE;
}

static void *add_timer(void (*expiry_handler)(void *userptr), void *userptr, uint16 timeout, timer_type type)
{
  if(unlikely((!expiry_handler) || (!timeout)))
  {
    return NULL;
  }

  assert(timeout < MAX_TIME_VALUE);

  ptimerinfo timerinfo = get_timer_info();
  ptimerinfo_node timerinfo_node;

  if(unlikely(!timerinfo))
  {
    return NULL;
  }
  
  timerinfo->userptr = userptr;
  timerinfo->expiry_handler = expiry_handler;
  timerinfo->timeout = timeout;
  timerinfo->type = type;

  timerinfo_node = _do_add_timer(timerinfo);

  return timerinfo_node;
}

void *add_one_shot_timer(void (*expiry_handler)(void *userptr), void *userptr, uint16 timeout)
{
  return add_timer(expiry_handler , userptr,timeout, ONE_SHOT);
}

void *add_repetitive_timer(void (*expiry_handler)(void *userptr), void *userptr, uint16 timeout)
{
  return add_timer(expiry_handler , userptr,timeout, CONTINUOUS);
}

int remove_timer(void *tinfo)
{
  if(unlikely(!tinfo))
  {
      assert(0);
    return -1;
  }
  ptimerinfo_node timerinfo_node = (ptimerinfo_node)tinfo;
  ptimerinfo timerinfo = ref_timer_info(timerinfo_node);

  if(unlikely((!timerinfo) || (!timerinfo->isrunning)))
  {
      assert(0);
    return -1;
  }
  if(remove_timerinfo(timerinfo_node, TWHEEL_LIST(timerinfo->slot)) < 0)
  {
      assert(0);
    return -1;
  }

  free_timer_info(timerinfo);

  return 0;
}


/* Restart Timer
 * 1. Remove timer from existing list
 * 2. Add timer in the correct list
 *
 * returns
 * -1 : if removal from the original list is unsuccess
 *  0: if timer is restarted
 */

int restart_timer(void *tinfo)
{
  if(unlikely(!tinfo))
  {
    return -1;
  }
  ptimerinfo_node timerinfo_node = (ptimerinfo_node)tinfo;
  ptimerinfo timerinfo = ref_timer_info(timerinfo_node);

  if(unlikely((!timerinfo) || (!timerinfo->isrunning)))
  {
    return -1;
  }

  return _do_restart_timer(timerinfo_node, timerinfo);
}

/* Modify Timer Val
 * 1. First remove the timer
 * 2. Change the timeout
 * 3. Enqueue the timernode in the new correct position
 *
 * returns
 * -1 : if removal from the original list is unsuccess
 *  0: if timer is restarted
 */

int modify_timer_val(void *tinfo, uint16 newtimeout)
{
  if(unlikely(!tinfo))
  {
    return -1;
  }
  ptimerinfo_node timerinfo_node = (ptimerinfo_node)tinfo;
  ptimerinfo timerinfo = ref_timer_info(timerinfo_node);

  if(unlikely((!timerinfo) || (!timerinfo->isrunning)))
  {
    return -1;
  }

  uint16 oldtimeout = timerinfo->timeout;
  timerinfo->timeout = newtimeout;

  if(unlikely(_do_restart_timer(timerinfo_node, timerinfo)) < 0)
  {
    timerinfo->timeout = oldtimeout;
    return -1;
  }

  return 0;
}

void stop_timer_list(struct dll *timer_list)
{
  /* Return Quickly from the obvious case */
  if((!timer_list) || (!timer_list->len))
  {
    return;
  }
  ptimerinfo_node curr_node, next_node;
  ptimerinfo curr_timer_info, next_timer_info;

  curr_node = get_timer_head(timer_list);

  curr_timer_info = ref_timer_info(curr_node);

  while(curr_node && curr_timer_info)
  {
    next_node = get_next_timer_node(curr_node);
    next_timer_info = ref_timer_info(curr_node);
    
    remove_timerinfo(curr_node, timer_list);
    free_timer_info(curr_timer_info);

    curr_node = next_node;
    curr_timer_info = next_timer_info;
  }

  return;
}
