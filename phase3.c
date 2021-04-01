/* ------------------------------------------------------------------------
	phase3.c

	University of Arizona South
	Computer Science 452


	Rantz Marion & Mark Whitson

------------------------------------------------------------------------ */


/* ------------------------- Includes ----------------------------------- */
#include <usloss.h>
#include <sems.h>
#include <libuser.h>
#include <usyscall.h>
#include <stddef.h>
#include <phase1.h>
#include <phase2.h>
#include <phase3.h>


/* ------------------------- Prototypes ----------------------------------- */
int start2(char *);
int spawn_real(char *name, int (*func)(char *), char *arg, int stack_size, int priority);
int wait_real(int *status);

extern int Spawn(char *name, int (*func)(char *), char *arg, int stack_size, int priority, int *pid);
extern int  Wait(int *pid, int *status);
extern void Terminate(int status);
extern void GetTimeofDay(int *tod);
extern void CPUTime(int *cpu);
extern void GetPID(int *pid);
extern int  SemCreate(int value, int *semaphore);
extern int  SemP(int semaphore);
extern int  SemV(int semaphore);
extern int  SemFree(int semaphore);
extern int  spawn_real(char *name, int (*func)(char *), char *arg, int stack_size, int priority);
extern int  wait_real(int *status);
extern void terminate_real(int exit_code);
extern int  semcreate_real(int init_value);
extern int  semp_real(int semaphore);
extern int  semv_real(int semaphore);
extern int  semfree_real(int semaphore);
extern int  gettimeofday_real(int *time);
extern int  cputime_real(int *time);
extern int  getPID_real(int *pid);

extern int start3(char * arg);


/* -------------------------- Globals ------------------------------------- */
proc_struct ProcTable[MAXPROC];
sem_struct  SemTable[MAXSEMS];
void (*sys_vec[MAXSYSCALLS])(sysargs * args);

/* -------------------------- Functions ----------------------------------- */

/* ------------------------------------------------------------------------
   Name - nullsys3
   Purpose - We initialize every system call handler as nullsys3
   Parameters - sysargs ptr
   Returns - N/A
   Side Effects - ??
   ----------------------------------------------------------------------- */
static void nullsys3(sysargs * args_ptr)
{
  console("nullsys3(): Invalid syscall %d\n", args_ptr->number);
  console("nullsys3(): process %d terminating\n", GetPID());
  terminate_real(1);
} /* nullsys3 */


/* ------------------------------------------------------------------------
   Name - start2
   Purpose - Initializes the process and semaphore table, and system call vector
   Parameters - arg
   Returns - zero for normal quit
   Side Effects - ??
   ----------------------------------------------------------------------- */
int start2(char *arg)
{
    int		pid;
    int		status;

    //initialize sys_vec
    for (int i=0; i<MAXSYSCALLS; i++)
    {
      sys_vec[i] = nullsys3;
    }

    sys_vec[SYS_SPAWN] =        Spawn;
    sys_vec[SYS_WAIT] =         Wait;
    sys_vec[SYS_TERMINATE] =    Terminate;
    sys_vec[SYS_SEMCREATE] =    SemCreate;
    sys_vec[SYS_SEMP] =         SemP;
    sys_vec[SYS_SEMV] =         SemV;
    sys_vec[SYS_SEMFREE] =      SemFree;
    sys_vec[SYS_GETTIMEOFDAY] = GetTimeofDay;
    sys_vec[SYS_CPUTIME] =      CPUTime;
    sys_vec[SYS_GETPID] =       GetPID;

    //initialize proc_table
    for (int i=0; i<MAXPROC; i++)
    {
      ProcTable[i].child_ptr =        NULL;
      ProcTable[i].next_sibling_ptr = NULL;
      ProcTable[i].parent_ptr =       NULL;
      ProcTable[i].next_sem_block =   NULL;
      ProcTable[i].name[0] =          '\0';
      ProcTable[i].start_arg[0] =     '\0';
      ProcTable[i].pid =              -1
      ProcTable[i].parent_pid =       -1;
      ProcTable[i].priority =         -1;
      ProcTable[i].func =             NULL;
      ProcTable[i].stack_size =       -1;
      ProcTable[i].num_children =     0;
      ProcTable[i].start_mbox =       MboxCreate(1, MAXLINE);
    }

    //initialize sem_table
    for (int i=0; i<MAXSEMS; i++)
    {
      SemTable[i].mutex_mbox = -1;
      SemTable[i].block_mbox = -1;
      SemTable[i].value =       0;
      SemTable[i].blocked =     0;
    }

    pid = spawn_real("start3", start3, NULL, 4*USLOSS_MIN_STACK, 3);
    pid = wait_real(&status);

    return status;
} /* start2 */
