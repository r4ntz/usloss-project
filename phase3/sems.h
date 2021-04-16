#include <phase1.h>

#ifndef _SEMS_H
#define _SEMS_H

#define MINPRIORITY 5
#define MAXPRIORITY 1

#define START2_PID  3
#define START3_PID  4

//status
#define EMPTY       0
#define ACTIVE      1
#define USED        2
#define WAIT_BLOCK  11

#endif

typedef struct proc_struct *proc_ptr;

typedef struct proc_struct
{
  proc_ptr child_ptr;
  proc_ptr next_sibling_ptr;
  proc_ptr parent_ptr;
  proc_ptr next_sem_block;

  char          name[MAXNAME]; //from phase1.h
  char          start_arg[MAXARG]; //also from phase1.h
  short         pid;
  short         parent_pid;
  int           priority;
  int           (*start_func)(char *); //where process begins
  unsigned int  stack_size;
  int           num_children;
  int           status;
  int           start_mbox;
} proc_struct;


typedef struct sem_struct
{
  int      mutex_mbox;
  int      block_mbox;
  int      value;
  int      blocked;
} sem_struct;
