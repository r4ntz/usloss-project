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
#include <string.h>
#include <phase1.h>
#include <phase2.h>
#include <phase3.h>


/* ------------------------- Prototypes ----------------------------------- */
extern int   start3(char *);

static void nullsys3(sysargs *args);
static void spawn(sysargs *args);
static void wait(sysargs *args);
static void terminate(sysargs *args);
static void semCreate(sysargs *args);
static void semP(sysargs *args);
static void semV(sysargs *args);
static void semFree(sysargs *args);
static void getTimeOfDay(sysargs *args);
static void cpuTime(sysargs *args);
static void getPID(sysargs *args);

int spawn_real(char *name, int(*func)(char *), char *arg, unsigned int stack_size, int priority);
int spawn_launch(char *args);
int wait_real(int *status);
int terminate_real(int status);
int sem_create_real(int value);
int semp_real(int semID);
int semv_real(int semID);
int sem_free_real(int semID);
int gettimeofday_real();
int cputime_real();
int getPID_real();


/* -------------------------- Globals ------------------------------------- */
proc_struct ProcTable[MAXPROC];
sem_struct  SemTable[MAXSEMS];
void (*sys_vec[MAXSYSCALLS])(sysargs * args);

int debugflag3 = 1;
int next_sem = 0;
/* -------------------------- Functions ----------------------------------- */

/* ------------------------------------------------------------------------
   Name - check_kernel_mode
   Purpose - Checks mode. Used before enabling and disabling interrupts
   Parameters - None
   Returns - Nothing
   Side Effects - If we are not currently in kernel mode, this halts
   ----------------------------------------------------------------------- */
void check_kernel_mode(char * function_name)
{
	if ((PSR_CURRENT_MODE & psr_get()) == 0)
	{
		console("Kernel Error: %s() not in kernel mode.\n", function_name);
		halt(1);
	}
} /*check_kernel_mode */


/* ------------------------------------------------------------------------
   Name - set_user_mode
   Purpose - Sets current mode to user mode (non-Kernel mode)
   Parameters - N/A
   Returns - N/A
   Side Effects - Affects processes which require kernel mode
   ----------------------------------------------------------------------- */
void set_user_mode()
{
  psr_set(psr_get() & ~PSR_CURRENT_MODE);
} /* set_user_mode */


/* ------------------------------------------------------------------------
   Name - spawn_launch
   Purpose - ??
   Parameters - arg
   Returns - ??
   Side Effects - ??
   ----------------------------------------------------------------------- */
int spawn_launch(char * arg)
{
  if (debugflag3)
  {
    console("spawn_launch(): starting\n");
  }
  check_kernel_mode("spawn_launch");

  int result = -1;

  MboxReceive(ProcTable[getpid() % MAXPROC].start_mbox, NULL, 0);

  proc_ptr this_proc = &ProcTable[getpid() % MAXPROC];

  if (!is_zapped())
  {
    set_user_mode();
    int (*func)(char *) = this_proc->start_func;
    char arg[MAXARG];
    strcpy(arg, this_proc->start_arg);

    //run the function
    result = (func)(arg);

    // --
    Terminate(result);
  }
  else
  {
      terminate_real(0);
  }

  console("spawn_launch(): should not see this message following Terminate!\n");
  return 0;
} /* spawn_launch */


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
  console("nullsys3(): process %d terminating\n", getpid());
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
  if (debugflag3)
  {
    console("start2(): starting\n");
  }
  check_kernel_mode("start2");

  int pid;
  int		status;

  //initialize sys_vec
  for (int i=0; i<MAXSYSCALLS; i++)
  {
    sys_vec[i] = nullsys3;
  }

  sys_vec[SYS_SPAWN] =        spawn;
  sys_vec[SYS_WAIT] =         wait;
  sys_vec[SYS_TERMINATE] =    terminate;
  sys_vec[SYS_SEMCREATE] =    semCreate;
  sys_vec[SYS_SEMP] =         semP;
  sys_vec[SYS_SEMV] =         semV;
  sys_vec[SYS_SEMFREE] =      semFree;
  sys_vec[SYS_GETTIMEOFDAY] = getTimeOfDay;
  sys_vec[SYS_CPUTIME] =      cpuTime;
  sys_vec[SYS_GETPID] =       getPID;

  //initialize proc_table
  for (int i=0; i<MAXPROC; i++)
  {
    ProcTable[i].child_ptr =        NULL;
    ProcTable[i].next_sibling_ptr = NULL;
    ProcTable[i].parent_ptr =       NULL;
    ProcTable[i].next_sem_block =   NULL;
    ProcTable[i].name[0] =          '\0';
    ProcTable[i].start_arg[0] =     '\0';
    ProcTable[i].pid =              -1;
    ProcTable[i].parent_pid =       -1;
    ProcTable[i].priority =         -1;
    ProcTable[i].start_func =             NULL;
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

static void spawn(sysargs *args)
{
  return;
}

static void wait(sysargs *args)
{
  return;
}

static void terminate(sysargs *args)
{
  return;
}

static void semCreate(sysargs *args)
{
  return;
}

static void semP(sysargs *args)
{
  return;
}

static void semV(sysargs *args)
{
  return;
}

static void semFree(sysargs *args)
{
  return;
}

static void getTimeOfDay(sysargs *args)
{
  return;
}

static void cpuTime(sysargs *args)
{
  return;
}

static void getPID(sysargs *args)
{
  return;
}

int spawn_real(char *name, int(*func)(char *arg), char *arg, unsigned int stack_size, int priority)
{
  if (debugflag3)
  {
    console("spawn_real(): starting\n");
  }
  check_kernel_mode("spawn_real");

  return 0;
}

int wait_real(int *status)
{
  return 0;
}

int terminate_real(int status)
{
  return 0;
}

int sem_create_real(int value)
{
  return 0;
}

int semp_real(int semID)
{
  return 0;
}

int semv_real(int semID)
{
  return 0;
}

int sem_free_real(int semID)
{
  return 0;
}

int gettimeofday_real()
{
  return sys_clock();
}

int cputime_real()
{
  return readtime();
}

int getPID_real()
{
  return getpid();
}

void add_child(int parent_id, int child_id)
{
  return;
}

void remove_child(int parent_id, int child_id)
{
  return;
}

int get_next_sem()
{
  while(SemTable[next_sem].mutex_mbox != -1)
  {
    next_sem++;
    if (next_sem >= MAXSEMS)
    {
      next_sem = 0;
    }
  }

  return next_sem;
}
