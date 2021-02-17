/* ------------------------------------------------------------------------
   Mark Whitson & Rantz Marion
   Last Edit: 2/16/2021 9:30PM.

   phase1.c

   CSCV 452

   TO-DO: debug and fix what hasn't been accounted for, dump_processes()

   CHANGES:
   -fixed zap(), fixed quit(), implemented removeZL()


   ------------------------------------------------------------------------ */

#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <stdio.h>
#include <phase1.h>
#include "kernel.h"

/* for getpid() */
#include <sys/types.h>
#include <unistd.h>

/* ------------------------- Prototypes ----------------------------------- */
int sentinel (char *); //from (void *) to (char *dummy)
extern int start1 (char *);
extern int check_io();
extern void (*int_vec[NUM_INTS])(int dev, void * unit);
extern void dump_processes(void);
void dispatcher(void);
void launch();
static void enableInterrupts();
static void check_deadlock();


/* -------------------------- Globals ------------------------------------- */

/* Patrick's debugging global variable... */
int debugflag = 1;

/* the process table */
proc_struct ProcTable[MAXPROC];

/* Process lists  */
proc_struct ReadyList[SENTINELPRIORITY];

/* current process ID */
proc_ptr Current;

/* the next pid to be assigned */
unsigned int next_pid = SENTINELPID;


/* -------------------------- Functions ----------------------------------- */
/* ------------------------------------------------------------------------
   Name - startup
   Purpose - Initializes process lists and clock interrupt vector.
	     Start up sentinel process and the test process.
   Parameters - none, called by USLOSS
   Returns - nothing
   Side Effects - lots, starts the whole thing
   ----------------------------------------------------------------------- */
void (*int_vec[NUM_INTS])(int dev, void * unit);

void init_process(int index) {
    check_mode();
    disableInterrupts();

    ProcTable[index].pid = -1;
    ProcTable[index].parent_ptr = NULL;
    ProcTable[index].next_proc_ptr = NULL;
    ProcTable[index].next_zappd_ptr = NULL;
    ProcTable[index].next_sibling_ptr = NULL;
    ProcTable[index].zapped = 0;
    ProcTable[index].time_sliced = 0;
    ProcTable[index].num_children = 0;
    ProcTable[index].status = READY;
    ProcTable[index].cpu_time = 0;
    ProcTable[index].start_time = 0;

    enableInterrupts();
}

void startup() {
   check_mode();

   int i;      /* loop index */
   int result; /* value returned by call to fork1() */

   /* initialize the process table */
   for (i = 0; i < MAXPROC; i++) {
     init_process(i);
   }

   Current =  &ProcTable[MAXPROC-1];

   /* Initialize the Ready list, etc. */
   if (DEBUG && debugflag)
      console("startup(): initializing the Ready & Blocked lists\n");

   /* Initialize the clock interrupt handler */
   int_vec[CLOCK_DEV] = clock_handler;

   /* startup a sentinel process */
   if (DEBUG && debugflag)
       console("startup(): calling fork1() for sentinel\n");
   result = fork1("sentinel", sentinel, NULL, USLOSS_MIN_STACK,
                   SENTINELPRIORITY);
   if (result < 0) {
      if (DEBUG && debugflag)
         console("startup(): fork1 of sentinel returned error, halting...\n");
      halt(1);
   }

   /* start the test process */
   if (DEBUG && debugflag)
      console("startup(): calling fork1() for start1\n");
   result = fork1("start1", start1, NULL, 2 * USLOSS_MIN_STACK, 1);
   if (result < 0) {
      console("startup(): fork1 for start1 returned an error, halting...\n");
      halt(1);
   }

   console("startup(): Should not see this message! ");
   console("Returned from fork1 call that created start1\n");

   return;
} /* startup */

/* ------------------------------------------------------------------------
   Name - finish
   Purpose - Required by USLOSS
   Parameters - none
   Returns - nothing
   Side Effects - none
   ----------------------------------------------------------------------- */
void finish() {
  check_mode();

  if (DEBUG && debugflag)
    console("in finish...\n");
} /* finish */


/* insertChild()
 * adds newly created child process to currently running
 * process. add this in fork1() once child is filled w/attributes.
 */
void insertChild(proc_ptr child) {
  proc_ptr walker = Current;
  if (walker->child_proc_ptr != NULL) {
    proc_ptr sibling = walker->child_proc_ptr;
    while (sibling->next_sibling_ptr != NULL) {
      sibling = sibling->next_sibling_ptr;
    }
    sibling->next_sibling_ptr = child;
  }
  else walker->child_proc_ptr = child;
}

proc_ptr get_proc(int pid) {
  proc_ptr walker = &ProcTable[pid % MAXPROC];
  if (walker->pid != pid) return NULL;
  else return walker;
}


/* Functions related to reading the elapsed time since
 * execution and duration a process has been running
 */

//returns CPU time (in milleseconds) used by current process
int readtime(void) {
  int curr_time_since_boot = sys_clock();
  int curr_time = read_cur_start_time();
  //we divide by 1000 since we need to convert to millseconds
  int cpu_time = (curr_time - curr_time_since_boot)/1000;

  return cpu_time;
}

//returns length of microseconds since program has started running..
int get_current_time(void) {
  int time_since_boot = sys_clock();
  return time_since_boot;
}

//checks to see if process has any time left for execution
void time_slice(void) {
  if (DEBUG && debugflag) console("time_slice(): started\n");
  check_mode();
  disableInterrupts();

  int elapsed_time = readtime();
  //this means that the time is up
  if (MAXTIME - elapsed_time <= 0) {
    Current->time_sliced++;
  }
  if (Current->time_sliced == 4) {
    Current->time_sliced = 0;
    dispatcher();
  }
  else enableInterrupts();
}

//just returns start_time attr which was assigned by get_current_time()
int read_cur_start_time(void) {
  return Current->start_time;
}

/* --------- */


/* rough implementaion for function used in phase2 */
int block_me(int new_status) {
  if (new_status <= 10) {
    console("block_me(): new_status is less than 10 (val: %d)\n", new_status);
    halt(1);
  }
  if (Current->zapped) return -1;
  return 0;
}

/* clock_handler()
 * Don't need to invoke this function. USLOSS invokes this
 * every 20 milliseconds (see USLOSS manual). After 4 approx. intervals it will
 * reach the MAXTIME we have set. time_slice() checks this
 */
void clock_handler(int dev, void * unit){
  static int interval = 0;
  interval++;
  if (DEBUG && debugflag) {
    console("clock_handler called. interval #%d\n", interval);
  }
  time_slice();
}

void removeRL(proc_ptr proc) {
  if (ReadyList[0].priority == -1) {
    console("removeRL(): ReadyList is empty.\n")
    halt(1);
  }
  proc_ptr walker = &ReadyList[0];
  proc_ptr prev;

  while (walker->next_proc_ptr != NULL) {
    if (proc->pid == walker->pid) break;
    prev = walker;
    walker = walker->next_proc_ptr;
  }
  prev->next_proc_ptr = walker->next_proc_ptr;
  return;
}

void insertRL(proc_ptr proc) {
  proc_ptr walker, previous;
  previous = NULL;
  walker = &ReadyList[0];
  if (proc->time_sliced) {
    while(walker->next_proc_ptr != NULL) {
      walker->next_proc_ptr;
    }
    proc->time_sliced = 0;
    walker->next_proc_ptr = proc;
  }
  else {
    while(walker != NULL && walker->priority <= proc->priority) {
      previous = walker;
      walker = walker->next_proc_ptr;
    }

    if (previous == NULL) {
      /*process goes at front of ReadyList */
      proc->next_proc_ptr = ReadyList;
      ReadyList = proc;
    }
    else {
      /*process goes after previous */
      previous->next_proc_ptr = proc;
      proc->next_proc_ptr = walker;
    }
  }

  return;
}

/* rough implementation for function used in phase2 */

int block_me(int new_status) {
  if (new_status <= 10) {
    console("block_me(): new_status must be larger than ten. val: %d\n", new_status);
    halt(1);
  }
  check_mode();
  disableInterrupts();

  Current->status = new_status;
  removeRL(ReadyList[(Current->priority - 1)]);
  dispatcher();

  if (Current->zappd) return -1;

  return 0;
}
int unblock_proc(int pid){
  if (Current->pid == pid) {
    return -2;
  }
  proc_ptr unblock_this = get_proc(pid);

  if (unblock_this != NULL) {
    if (unblock_this->status <= 10) return -2;
    else if (unblock_this->status == BLOCKED) return -2;
    else if (unblock_this->zapped) return -1;

    insertRL(unblock_this);
    return 0;
  }
  else return -2;
}
/* ------------------------------------------------------------------------
   Name - fork1
   Purpose - Gets a new process from the process table and initializes
             information of the process.  Updates information in the
             parent process to reflect this child process creation.
   Parameters - the process procedure address, the size of the stack and
                the priority to be assigned to the child process.
   Returns - the process id of the created child or -1 if no child could
             be created or if priority is not between max and min priority.
   Side Effects - ReadyList is changed, ProcTable is changed, Current
                  process information changed
   ------------------------------------------------------------------------ */
int fork1(char *name, int (*f)(char *), char *arg, int stacksize, int priority)
{
   check_mode();
   disableInterrupts();
   int proc_slot;

   if (DEBUG && debugflag)
      console("fork1(): creating process %s\n", name);

   /* test if in kernel mode; halt if in user mode */
   if((PSR_CURRENT_MODE & psr_get()) == 0) {
     console("Kernel Error: Not in kernel mode.\n");
     halt(1);
   }
   /* Return if stack size is too small */
   if (stacksize < USLOSS_MIN_STACK) {
     console("stacksize is too small.\n");
     halt(1);
   }


   /* Check for valid priority (ADDED) */
   else if ((priority > MINPRIORITY || priority < MAXPRIORITY) && f != sentinel) {
     	 console("%s's priority is %d. max: %d, min: %d\n", name, priority, MINPRIORITY, MAXPRIORITY);
	 //console("invalid priority given.\n");
     halt(1);
   }

   /* find an empty slot in the process table */
   proc_slot = next_pid % MAXPROC;
   while (ProcTable[proc_slot].priority != -1) {
     next_pid++;
     proc_slot = next_pid % MAXPROC;
   }

   /* fill-in entry in process table */
   if ( strlen(name) >= (MAXNAME - 1) ) {
      console("fork1(): Process name is too long.  Halting...\n");
      halt(1);
   }
   strcpy(ProcTable[proc_slot].name, name);
   ProcTable[proc_slot].start_func = f;
   if ( arg == NULL )
      ProcTable[proc_slot].start_arg[0] = '\0';
   else if ( strlen(arg) >= (MAXARG - 1) ) {
      console("fork1(): argument too long.  Halting...\n");
      halt(1);
   }
   else
      strcpy(ProcTable[proc_slot].start_arg, arg);

    ProcTable[proc_slot].pid = next_pid++;

    ProcTable[proc_slot].start_time = (int) get_current_time(); //NOTE: added this

   /* Initialize context for this process, but use launch function pointer for
    * the initial value of the process's program counter (PC)
    */

   ProcTable[proc_slot].stack = (char *) malloc(stacksize);
   ProcTable[proc_slot].stacksize = stacksize;

   context_init(&(ProcTable[proc_slot].state), psr_get(),
                ProcTable[proc_slot].stack,
                ProcTable[proc_slot].stacksize, launch);

   /* for future phase(s) */
   p1_fork(ProcTable[proc_slot].pid);

   //NOTE: added 2/9. **current should be swapped when its status changes
   if (Current->pid > -1) {
     insertChild(&ProcTable[proc_slot]);
     ProcTable[proc_slot].parent = Current;
   }

   insertRL(&ProcTable[proc_slot]);
   ProcTable[proc_slot].status = READY;

   if (f != sentinel) {
     dispatcher();
   }

   enableInterrupts();
   return ProcTable[proc_slot].pid;
}

//unblockes all zapped processes in current
void removeZL(void) {
  proc_ptr walker = Current->next_zappd_ptr;
  while (walker != NULL) {
    walker->status = READY;
    insertRL(walker);
    Current->zapped--;
    walker = walker->next_zappd_ptr;
  }

  Current->next_zappd_ptr = NULL;
}

void insertZL(proc_ptr zap_this) {
  proc_ptr walker = zap_this;
  while (walker->next_zappd_ptr != NULL) {
    walker = walker->next_zappd_ptr;
  }
  Current->zapped++;
  walker->next_zappd_ptr = Current;
}

int is_zapped(void) {
  if (Current->zapped > 0) return 1;
  else return 0;
}

/* zap() does not return until zapped process has quit.
 *  returns -1 if calling process itself was zapped while in zap
 *  returns 0 if the zapped process has already quit
 *
 *  NOTE: think of creating a function that removes procs from readylist
 */

int zap(int pid) {
  if (DEBUG && debugflag) console("zap(): starting\n");
  check_mode();
  disableInterrupts();

  //Current can't be zapped
  if (Current->pid == pid) {
    console("zap(): can't zap self\n");
    halt(1);
  }

  proc_ptr zap_parent = get_proc(pid);

  if (zap_this == NULL) {
      console("zap(): process (pid: %d) does not exist\n", pid);
      halt(1);
  }
  else if (zap_this->status == QUIT) {
    if (Current->zapped) return -1;
    else return 0;
  }

  insertZL(zap_this);
  Current=>status = BLOCKED;
  removeRL(Current);
  dispatcher();

  enableInterrupts();

  if (Current->zapped) return -1;
  return 0;

}

/* ------------------------------------------------------------------------
   Name - launch
   Purpose - Dummy function to enable interrupts and launch a given process
             upon startup.
   Parameters - none
   Returns - nothing
   Side Effects - enable interrupts
   ------------------------------------------------------------------------ */
void launch()
{
   int result;

   if (DEBUG && debugflag)
      console("launch(): started\n");

   /* Enable interrupts */
   enableInterrupts();

   /* Call the function passed to fork1, and capture its return value */
   result = Current->start_func(Current->start_arg);

   if (DEBUG && debugflag)
      console("Process %d returned to launch\n", Current->pid);

   quit(result);

} /* launch */


/* ------------------------------------------------------------------------
   Name - join
   Purpose - Wait for a child process (if one has been forked) to quit.  If
             one has already quit, don't wait.
   Parameters - a pointer to an int where the termination code of the
                quitting process is to be stored.
   Returns - the process id of the quitting child joined on.
		-1 if the process was zapped in the join
		-2 if the process has no children
   Side Effects - If no child process has quit before join is called, the
                  parent is removed from the ready list and blocked.
   ------------------------------------------------------------------------ */
int join(int * code) {
  check_mode();
  disableInterrupts();

  int all_dead = 1;

  if (DEBUG && debugflag) console("join(): started\n");

  //if there's no children then return -2
  if (Current->num_children == 0) {
    if (DEBUG && debugflag) console("join(): no children!\n");
    return -2;
  }

  //check to see if children quit

  if (DEBUG && debugflag) console("join(): checking to see if children quit\n");
  proc_ptr curr_child = Current->child_proc_ptr;
  proc_ptr earliest_child = NULL;

  while (curr_child->next_proc_ptr != NULL) {
    if (curr_child->status == READY) all_dead = 0;
    else if (curr_child->status == QUIT && earliest_child == NULL) {
      earliest_child = curr_child;
    }
    curr_child = curr_child->next_sibling_ptr;
  }

  if (all_dead) {
    if (DEBUG && debugflag) console("join(): all children dead. removing from ReadyList and blocking\n");
    Current->status = BLOCKED;
    removeRL(Current);
    dispatcher();
  }
  else if (earliest_child != NULL) {
    *status = earliest_child->status;
  }

  enableInterrupts();
  return earliest_child->pid;
}


/* ------------------------------------------------------------------------
   Name - quit
   Purpose - Stops the child process and notifies the parent of the death by
             putting child quit info on the parents child completion code
             list.
   Parameters - the code to return to the grieving parent
   Returns - nothing
   Side Effects - changes the parent of pid child completion status list.
   ------------------------------------------------------------------------ */
void quit(int code) {
  if (DEBUG && debugflag) console("quit(): started\n");
  check_mode();
  disable_interrupts();

  Current->status = QUIT;
  removeRL(Current);

  proc_ptr curr_child = Current->child_proc_ptr;
  if (curr_child != NULL) {
    while (curr_child != NULL) {
      if (curr_child->status != QUIT) {
        console("Process (pid %d) tried to quit with active children.\n", Current->pid);
        halt(1);
      }
      curr_child = curr_child->next_sibling_ptr;
    }
  }
  //unblock all processes that are zapped
  if (Current->zapped) removeZL();

  //free memory allocated to Current's stack and wipe attributes
  free(Current->stack);
  this_pid = Current->pid % MAXPROC;
  init_process(this_pid);

  p1_quit(Current->pid);

  //this is so that the next process can run
  dispatcher();

} /* quit */

/* helper function for dispatcher(). grabs procs with highest priority value */
proc_ptr get_highest_priority(int ProcTable_index) {
  console("get_highest_priority(): finding process with highest priority\n")
  proc_ptr return_this = NULL;
  for (int i=0; i<SENTINELPRIORITY; i++) {
    if (return_this == NULL) {
      return_this = &ProcTable[ProcTable_index];
    }
    else if (return_this->priority > ProcTable[ProcTable_index].priority) {
      return_this = &ProcTable[ProcTable_index];
    }
    else continue;
  }

  if (return_this != NULL) {
    console("get_highest_priority(): found process\n")
    return return_this;
  }

  else {
    console("get_highest_priority(): could not any ready processes\n");
    return NULL;
  }
}

/* ------------------------------------------------------------------------
   Name - dispatcher
   Purpose - dispatches ready processes.  The process with the highest
             priority (the first on the ready list) is scheduled to
             run.  The old process is swapped out and the new process
             swapped in.
   Parameters - none
   Returns - nothing
   Side Effects - the context of the machine is changed
   ----------------------------------------------------------------------- */

void dispatcher(void) {
   console("dispatcher(): started.\n");
   check_mode();
   disableInterrupts();

   proc_ptr next_process = NULL;
   proc_ptr temp_process = NULL;

   if (Current->status == RUNNING) {
     Current->status = READY;
     removeRL(Current);
     for (int i=0; i<SENTINELPRIORITY-1; i++) {
        temp_process = get_highest_priority(i);
        if (next_process == NULL) {
          next_process = temp_process;
        }
        else {
          if (next_process->priority > temp_process->priority) {
            next_process = temp_process;
          }
          else continue;
        }
     }
   }


   //as long as current process is running, it will fetch a process with
   //higher priority, swap it with current process, reset the time related
   //attributes
  if (next_process != NULL) {
    console("dispatcher(): found a suitable process for replacement\n");

    proc_ptr old_process = Current;
    insertRL(old_process);
    Current = next_process;
    Current->status = RUNNING;

    if (old_process != Current) {
      if (old_process->pid > -1) {
        old_process->cpu_time += readtime();
      }
      Current->cpu_time = 0;
      Current->start_time = get_current_time();
    }

    p1_switch(old_process->pid, Current->pid);
    enableInterrupts();
    context_switch(&old_process->state, Current->state);
  }

  else {
    enableInterrupts();
    console("dispatcher(): current process is not running..\n");
  }
} /* dispatcher */


/* ------------------------------------------------------------------------
   Name - sentinel
   Purpose - The purpose of the sentinel routine is two-fold.  One
             responsibility is to keep the system going when all other
	     processes are blocked.  The other is to detect and report
	     simple deadlock states.
   Parameters - none
   Returns - nothing
   Side Effects -  if system is in deadlock, print appropriate error
		   and halt.
   ----------------------------------------------------------------------- */
int sentinel (char * dummy) {
   if (DEBUG && debugflag)
      console("sentinel(): called\n");
   while (1) {
      check_deadlock();
      waitint();
   }
   return 1;
} /* sentinel */


/* check_deadlock()
 * This just checks to see if there are still running processes
 */
static void check_deadlock() {
  int blockd = 0;
  int rdy = 0;
  for (int i=0; i<SENTINELPRIORITY-1; i++) {
    if (ProcTable[i].status == READY) {
      rdy = 1;
      break;
    }
    else if (ProcTable[i].status = BLOCKED) {
      blockd = 1;
      break;
    }
    else continue;
  }

  if (blockd) return;
  else if (ready) {
    console("check_deadlock(): only sentinel should be left.\n")
    halt(1);
  }
  else halt(0);
}


static void enableInterrupts() {
  //if we're not in kernel mode then halt
  if ((PSR_CURRENT_MODE & psr_get()) == 0) {
    console("Kernel Error: Not in kernel mode, may not enable interrupts\n");
    halt(1);
  }
  //if we are in kernel mode, then we can change bits
  else psr_set(psr_get() | PSR_CURRENT_INT);
}

/*
 * Disables the interrupts.
 */
void disableInterrupts() {
  /* turn the interrupts OFF iff we are in kernel mode */
  if((PSR_CURRENT_MODE & psr_get()) == 0) {
    //not in kernel mode
    console("Kernel Error: Not in kernel mode, may not disable interrupts\n");
    halt(1);
  }
  else psr_set( psr_get() & ~PSR_CURRENT_INT );

  return;
}
/* disableInterrupts */


/*
 * check if process is in kernel mode and halt if it isnt
 */

void check_mode(void) {
  if ((PSR_CURRENT_MODE & psr_get()) == 0) {
    console("Kernel Error: Not in kernel mode.\n");
    halt(1);
  }
}


/* ------------------------------------------------------------------------
   Name - dump_processes
   Purpose - Print process information to the console.
		For each PCB in the process:
			-table print (at a minimum) its PID
			-parent’s PID
			-priority
			-process status (e.g. unused,running, ready, blocked, etc.)
			-# of children
			-CPU time consumed
			-name

   Parameters - none
   Returns - nothing
   Side Effects -  ????

   ----------------------------------------------------------------------- */

void dump_processes(void) {
	return;
}
/* dump_processes */
