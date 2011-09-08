#include "timer.h"
#include "list.h"
#include <signal.h>

#include <stdio.h>
#include <stdlib.h>

#define TEN_SEC_EXP 10000
#define CONTINUOUS_EXPIRY 5000

int *test1, *test2;
int cond = 1;


  void *cont_timer, *one_shot_timer, *one_shot_2;

void siginthandler(int cause, siginfo_t *info, void *uctxt)
{
  cond = 0;
}

void register_sigint_handler()
{
  struct sigaction sa;

  sa.sa_sigaction = siginthandler;

  sigemptyset(&sa.sa_mask);

  sa.sa_flags = SA_SIGINFO;

  if(sigaction(SIGINT, &sa, 0))
  {
    perror("sigaction");
    exit(1);
  }
}

void timer1(void *userptr)
{
  int *test = (int *)userptr;
  printf("%d This is timer1 expiry: %d\n", CONTINUOUS_EXPIRY, *test);
  (*test)++;
  return;
}

void timer2(void *userptr)
{
  int *test = (int *)userptr;
  printf("%d This is timer2 expiry: %d\n", TEN_SEC_EXP, *test);
  (*test)++;
  modify_timer_val(one_shot_2, 1000);
  return;
}


int main()
{
//  register_sigint_handler();
  start_timer();


  test1 = malloc(sizeof(int));
  *test1 = 0;

  test2 = malloc(sizeof(int));
  *test2 = 0;

  one_shot_timer = add_one_shot_timer(timer1, test2, CONTINUOUS_EXPIRY);
  cont_timer = add_one_shot_timer(timer1, test1, CONTINUOUS_EXPIRY);
  one_shot_2 = add_one_shot_timer(timer2, test2, CONTINUOUS_EXPIRY);
      
  while(cond)
  {
 /*   if(*test1 == 3)
    {
      modify_timer_val(cont_timer, CONTINUOUS_EXPIRY/5);
    }

    if(*test2 == 1)
    {
      restart_timer(one_shot_timer);
    }
    */
    if(*test2 == 1)
    {
      (*test2)++;
    }
  }

  return 0;
}
