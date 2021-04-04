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
void terminate_real(int status);
int sem_create_real(int value);
int semp_real(int semID);
int semv_real(int semID);
int sem_free_real(int semID);
int gettimeofday_real();
int cputime_real();
int getPID_real();

extern int   start3(char *);

/* -------------------------- Globals ------------------------------------- */
proc_struct ProcTable[MAXPROC];
sem_struct  SemTable[MAXSEMS];

int debugflag3 = 0;
int num_sems = 0;
int next_sem = 0;
int num_processes = 3;
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
   Name - add_child
   Purpose - Self-explanatory
   Parameters - parent pid and child pid
   Returns - N/A
   Side Effects - ??
   ----------------------------------------------------------------------- */
void add_child(int parent_id, int child_id)
{
  if (debugflag3)
  {
    console("add_child(): adding child with pid: %d and parent: %d\n", child_id, parent_id);
  }
  check_kernel_mode("add_child");

  parent_id = parent_id % MAXPROC;
  child_id =  child_id % MAXPROC;

  ProcTable[parent_id].num_children++;

  if (ProcTable[parent_id].child_ptr == NULL)
  {
    if (debugflag3) console("add_child(): adding parent's first child\n");
    ProcTable[parent_id].child_ptr = &ProcTable[child_id];
  }

  else
  {
    proc_ptr child = ProcTable[parent_id].child_ptr;
    while (child->next_sibling_ptr != NULL)
    {
      child = child->next_sibling_ptr;
    }

    if (debugflag3)
    {
      console("add_child(): inserting %d's sibling %d\n", child->pid, child_id);
    }

    child->next_sibling_ptr = &ProcTable[child_id];
  }

  ProcTable[child_id].parent_ptr = &ProcTable[parent_id];

} /* add_child */


/* ------------------------------------------------------------------------
   Name - remove_child
   Purpose - Self-explanatory
   Parameters - parent pid and child pid
   Returns - N/A
   Side Effects - ??
   ----------------------------------------------------------------------- */
void remove_child(int parent_id, int child_id)
{
  if (debugflag3)
  {
    console("remove_child(): removing child with pid: %d and parent: %d\n", child_id, parent_id);
  }
  check_kernel_mode("remove_child");

  ProcTable[parent_id].num_children--;

  if (ProcTable[parent_id].child_ptr == NULL) return;

  if (ProcTable[parent_id].child_ptr->pid == child_id)
  {
    if (debugflag3) console("remove_child(): child is head. removing\n");
    ProcTable[parent_id].child_ptr = ProcTable[parent_id].child_ptr->next_sibling_ptr;
  }

  else
  {
    if (debugflag3) console("remove_child(): searching for child to remove\n");
    proc_ptr child = ProcTable[parent_id].child_ptr;

    while(child->next_sibling_ptr != NULL)
    {
      if (child->next_sibling_ptr->pid == child_id)
      {
        child->next_sibling_ptr = child->next_sibling_ptr->next_sibling_ptr;
        break;
      }
      child = child->next_sibling_ptr;
    }
  }
} /* remove_child */



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

  int result = -1;

  MboxReceive(ProcTable[getpid() % MAXPROC].start_mbox, 0, 0);

  proc_ptr this_proc = &ProcTable[getpid() % MAXPROC];

  if (!is_zapped())
  {
    if (debugflag3) console("spawn_launch(): setting up process\n");
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
  if (debugflag3)
  {
    console("spawn(): starting\n");
  }
  check_kernel_mode("spawn");

  num_processes++;

  char *name;
  int (*func)(char *);
  char *arg;
  int stack_size;
  int priority;

  if (num_processes > MAXPROC)
  {
    args->arg1 = (void *) -1;
    num_processes--;
    return;
  }

  func = args->arg1;
  arg = args->arg2;
  stack_size = (int) args->arg3;
  priority = (int) args->arg4;
  name = args->arg5;

  int pid = spawn_real(name, func, arg, stack_size, priority);

  args->arg1 = (void *) pid;
  args->arg4 = (void *) 0;

  set_user_mode();
  return;
}

static void wait(sysargs *args)
{
  if (debugflag3)
  {
    console("wait(): starting\n");
  }
  check_kernel_mode("wait");

  int status;
  int pid = wait_real(&status);

  args->arg1 = (void *) pid;
  args->arg2 = (void *) status;
  if (pid < 0) args->arg4 = (void *) -1;
  else args->arg4 = (void *) 0;

  if (is_zapped()) terminate_real(1);

  set_user_mode();
  return;
}

static void terminate(sysargs *args)
{
  if (debugflag3)
  {
    console("terminate(): starting\n");
  }
  check_kernel_mode("terminate");

  int pid = (int) args->arg1;
  terminate_real(pid);
  set_user_mode();
  return;
}

static void semCreate(sysargs *args)
{
  if (debugflag3)
  {
    console("semCreate(): starting\n");
  }
  check_kernel_mode("semCreate");

  //int address = sem_create_real((int) args->arg1);
  int value = (int) args->arg1;

  if (value < 0 || num_sems == MAXSEMS)
  {
    args->arg4 = (void *) -1;
  }
  else
  {
    int handle = sem_create_real(value);
    args->arg4 = 0;
    args->arg1 = (void *) handle;
  }

  return;
}

static void semP(sysargs *args)
{
  if (debugflag3)
  {
    console("semP(): starting\n");
  }

  int sem_id = (int) args->arg1;
  int result = semp_real(sem_id);

  args->arg4 = (void *) result;

  return;
}

static void semV(sysargs *args)
{
  if (debugflag3)
  {
    console("semV(): starting\n");
  }
  check_kernel_mode("semV");

  int sem_id = (int) args->arg1;
  if (sem_id < 0)
  {
    args->arg4 = (void *) (int) -1;
  }
  else
  {
    args->arg4 = 0;
  }

  semv_real(sem_id);

  return;
}

static void semFree(sysargs *args)
{
  if (debugflag3)
  {
    console("semFree(): starting\n");
  }

  int sem_id = (int) args->arg1;
  if (sem_id == -1)
  {
    args->arg4 = (void *) -1;
  }
  else
  {
    int result = sem_free_real(sem_id);
    args->arg4 = (void *) result;
  }

  return;
}

static void getTimeOfDay(sysargs *args)
{
  if (debugflag3)
  {
    console("getTimeOfDay(): starting\n");
  }

  int result = gettimeofday_real();
  args->arg1 = (void *) result;

  return;
}

static void cpuTime(sysargs *args)
{
  if (debugflag3)
  {
    console("cpuTime(): starting\n");
  }

  int result = cputime_real();
  args->arg1 = (void *) result;

  return;
}

static void getPID(sysargs *args)
{
  if (debugflag3)
  {
    console("getPID(): starting\n");
  }
  int result = getPID_real();
  args->arg1 = (void *) result;

  return;
}

int spawn_real(char *name, int(*func)(char *arg), char *arg, unsigned int stack_size, int priority)
{
  if (debugflag3)
  {
    console("spawn_real(): starting\n");
  }
  check_kernel_mode("spawn_real");

  int kidpid = fork1(name, spawn_launch, arg, stack_size, priority);

  if (kidpid < 0)
  {
    return -1;
  }

  int slot = kidpid % MAXPROC;

  ProcTable[slot].pid = kidpid;
  strcpy(ProcTable[slot].name, name);
  if (arg != NULL)
  {
    strcpy(ProcTable[slot].start_arg, arg);
  }
  ProcTable[slot].priority = priority;
  ProcTable[slot].start_func = func;
  ProcTable[slot].stack_size = stack_size;
  ProcTable[slot].parent_pid = getpid();

  add_child((int) getpid(), kidpid);

  if (debugflag3)
  {
    console("spawn_real(): sending message\n");
  }
  MboxSend(ProcTable[slot].start_mbox, 0, 0);

  if (is_zapped())
  {
    terminate_real(0);
  }

  return kidpid;
} /* spawn_real */


int wait_real(int *status)
{
  if (debugflag3)
  {
    console("wait_real(): started. curr pid: %d - parent pid: %d\n", getpid(), ProcTable[getpid() % MAXPROC].parent_pid);
  }

  int result = join(status);

  if(is_zapped())
  {
    terminate_real(0);
  }

  return result;
}

void terminate_real(int status)
{
  if (debugflag3)
  {
    console("terminate_real(): started. clearing pid: %d\n", getpid());
  }

  proc_ptr this_proc = &ProcTable[getpid() % MAXPROC];

  //check if there are any children
  while (1)
  {
    proc_ptr child = this_proc->child_ptr;
    if (child == NULL) break;
    else
    {
      if (debugflag3)
      {
        console("terminate_real(): found child. removing and zapping, pid: %d\n", child->pid);
      }
      remove_child(this_proc->pid, this_proc->child_ptr->pid);
      zap(child->pid);
    }
  }

  if (debugflag3)
  {
    console("terminate_real(): removing process from parent and clearing attrs, pid: %d\n", getpid());
  }

  remove_child(this_proc->parent_pid, this_proc->pid);

  //reset attrs
  int slot = this_proc->pid % MAXPROC;

  ProcTable[slot].child_ptr = NULL;
  ProcTable[slot].next_sibling_ptr = NULL;
  ProcTable[slot].parent_ptr = NULL;
  ProcTable[slot].name[0] = '\0';
  ProcTable[slot].start_arg[0] = '\0';
  ProcTable[slot].pid = -1;
  ProcTable[slot].parent_pid = -1;
  ProcTable[slot].priority = -1;
  ProcTable[slot].start_func = NULL;
  ProcTable[slot].stack_size = -1;
  ProcTable[slot].num_children = 0;
  MboxRelease(ProcTable[slot].start_mbox);
  ProcTable[slot].start_mbox = MboxCreate(0, MAXLINE);

  num_processes--;

  if (debugflag3)
  {
    console("terminate_real(): process quitting, pid: %d\n", getpid());
  }

  quit(status);

}

int get_next_sem()
{
  if (debugflag3)
  {
    console("get_next_sem(): starting\n");
  }

  while(SemTable[next_sem].mutex_mbox != -1)
  {
    next_sem++;
    if (debugflag3)
    {
      console("get_next_sem(): mutex_mbox is: %d - next_sem is: %d\n", SemTable[next_sem].mutex_mbox, next_sem);
    }
    if ((next_sem) >= MAXSEMS)
    {
      if (debugflag3) console("get_next_sem(): reached MAXSEMS. resetting to -1\n");
      next_sem = -1;
      break;
    }
  }

  if (debugflag3)
  {
    console("get_next_sem(): returning next_sem: %d\n", next_sem);
  }

  return next_sem;
}

int sem_create_real(int value)
{
  if (debugflag3)
  {
    console("sem_create_real(): starting\n");
  }
  check_kernel_mode("sem_create_real()");

  // --
  if (num_sems > MAXSEMS)
  {
    return -1;
  }

  int mutex_mbox = MboxCreate(1, 0);
  if(mutex_mbox == -1)
  {
    return -1;
  }

  int blocked_mbox = MboxCreate(value, 0);
  if (blocked_mbox == -1)
  {
    return -1;
  }

  num_sems++;
  int sem = get_next_sem();
  SemTable[sem].mutex_mbox = mutex_mbox;
  SemTable[sem].block_mbox = blocked_mbox;
  SemTable[sem].value = value;
  SemTable[sem].blocked = 0;

  return sem;
}

int semp_real(int sem_id)
{
  if (debugflag3)
  {
    console("semp_real(): starting\n");
  }
  check_kernel_mode("semp_real");

  if (SemTable[sem_id].mutex_mbox == -1)
  {
    return -1;
  }

  int mutex_mbox = SemTable[sem_id].mutex_mbox;
  int blocked_mbox = SemTable[sem_id].block_mbox;

  MboxSend(mutex_mbox, 0, 0);

  int broke = 0;
  while (SemTable[sem_id].value <=0)
  {
    SemTable[sem_id].blocked++;
    MboxReceive(mutex_mbox, 0, 0);
    MboxSend(blocked_mbox, 0, 0);

    if (is_zapped())
    {
      terminate_real(0);
    }

    if (SemTable[sem_id].mutex_mbox == -1)
    {
      broke = 1;
      break;
    }

    MboxSend(mutex_mbox, 0, 0);
  }

  if (!broke)
  {
    SemTable[sem_id].value--;
    MboxReceive(mutex_mbox, 0, 0);
  }

  else
  {
    terminate_real(1);
  }

  return 0;
}

int semv_real(int sem_id)
{
  if (debugflag3)
  {
    console("semv_real(): starting\n");
  }
  check_kernel_mode("semv_real");

  if (SemTable[sem_id].mutex_mbox == -1)
  {
    return -1;
  }

  int mutex_mbox = SemTable[sem_id].mutex_mbox;
  int blocked_mbox = SemTable[sem_id].block_mbox;

  MboxSend(mutex_mbox, 0, 0);
  SemTable[sem_id].value++;

  //check for blocked processes
  if (SemTable[sem_id].blocked > 0)
  {
    MboxReceive(blocked_mbox, 0, 0);
    SemTable[sem_id].blocked--;
  }
  else SemTable[sem_id].blocked++;

  MboxReceive(mutex_mbox, 0, 0);

  if (is_zapped())
  {
    terminate_real(0);
  }

  return 0;
}

int sem_free_real(int sem_id)
{
  if (debugflag3)
  {
    console("sem_free_real(): starting\n");
  }
  check_kernel_mode("sem_free_real");

  if (SemTable[sem_id].mutex_mbox == -1)
  {
    return -1;
  }

  SemTable[sem_id].mutex_mbox = -1;

  int result = 0;

  //if there are blocked processes wake them up
  if (SemTable[sem_id].blocked > 0)
  {
    result = 1;
    int i = 0;
    while (i < SemTable[sem_id].blocked)
    {
      MboxReceive(SemTable[sem_id].block_mbox, 0, 0);
      i++;
    }
  }

  //remove and release sems
  SemTable[sem_id].block_mbox = -1;
  SemTable[sem_id].value = -1;
  SemTable[sem_id].blocked = 0;

  MboxRelease(SemTable[sem_id].mutex_mbox);
  MboxRelease(SemTable[sem_id].block_mbox);

  if (is_zapped())
  {
    terminate_real(0);
  }

  num_sems--;

  return result;
}

int gettimeofday_real()
{
  if (debugflag3)
  {
    console("gettimeofday_real(): starting\n");
  }
  int time = sys_clock();

  return time;
}

int cputime_real()
{
  if (debugflag3)
  {
    console("cputime_real(): starting\n");
  }
  return readtime();
}

int getPID_real()
{
  if (debugflag3)
  {
    console("getPID_real(): starting\n");
  }
  return getpid();
}
