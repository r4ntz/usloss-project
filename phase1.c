/* ------------------------------------------------------------------------
   Mark Whitson & Rantz Marion
   Last Edit: 2/8/2021 7:45PM.

   phase1.c

   CSCV 452

   TO-DO: implement zap(), fix and debug other functions, implement clock_handler

   CHANGES:
   added check_ready_list, check_blocked_list, removeBL

   ------------------------------------------------------------------------ */

#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <stdio.h>
#include <sys/time.h>
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
proc_ptr ReadyList;
proc_ptr BlockedList; //for processes that end up being zapped..

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
void startup()
{
   int i;      /* loop index */
   int result; /* value returned by call to fork1() */

   /* initialize the process table */
   //NOTE: adjust other attributes if necessary. just linking siblings
   for (i = 0; i < MAXPROC; i++) {
     ProcTable[i].priority = 0; //need to initialize value otherwise undefined behavior
     if ((i+1) != MAXPROC) {
       ProcTable[i].next_sibling_ptr = &ProcTable[i+1];
     }
   }
   /* Initialize the Ready list, etc. */
   if (DEBUG && debugflag)
      console("startup(): initializing the Ready & Blocked lists\n");


   /* Initialize the clock interrupt handler */
   //NOTE: defer working on this until fork1, join, quit, and dispatcher are working

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
void finish()
{
   if (DEBUG && debugflag)
      console("in finish...\n");
} /* finish */


int getpid(void) {
  int pid = (int) getpid();
  return pid;
}

long int get_current_time(void) {
  struct timeval current_time;
  gettimeofday(&current_time, NULL);
  return current_time.tv_usec;
}

void time_slice(void) {

}

int read_cur_start_time(void) {
  return Current->start_time;
}

/* rough implementaion for function used in phase2 */
int block_me(int new_status) {
  if (new_status <= 10) {
    console("block_me(): new_status is greater than 10 (val: %d)\n", new_status);
    halt(1);
  }

  int zappd;
  if ((zappd = is_zapped()) == 1) {
      return -1;
  }

  //insertBL(Current);

  return 0;
}

void clock_handler(int dev, void * unit){
  return;
}


static void insertRL(proc_ptr proc) {
  proc_ptr walker, previous;
  previous = NULL;
  walker = ReadyList;

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

  return;
}

/* rough implementation for function used in phase2 */
int unblock_proc(int pid){
  if (Current->pid == pid) {
    return -2;
  }
  int found = 0;
  proc_ptr walker = BlockedList;
  proc_ptr prev = BlockedList;
  while (walker != NULL) {
    if (walker->pid == pid) {
      found = 1;
      break;
    }
    walker = walker->next_proc_ptr;
  }

  if (found){
    if (walker->status <= 10) return -2;
    else if (walker->zapped) return -1;
    proc_ptr nowReady = walker;
    prev->next_proc_ptr = walker->next_proc_ptr;
    insertRL(nowReady);
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
   int proc_slot;

   if (DEBUG && debugflag)
      console("fork1(): creating process %s\n", name);

   /* test if in kernel mode; halt if in user mode */
   if((PSR_CURRENT_MODE & psr_get()) == 0) {
     console("Kernel Error: Not in kernel mode.\n");
     halt(1);
   }
   /* Return if stack size is too small */
   if (stacksize <= USLOSS_MIN_STACK) {
     console("stacksize is too small.\n");
     halt(1);
   }

   /* Check for valid priority (ADDED) */
   if (priority < LOWEST_PRIORITY || priority > HIGHEST_PRIORITY) {
     console("invalid priority given.\n");
     halt(1);
   }

   /* find an empty slot in the process table */
   proc_slot = 0;
   proc_ptr currProccess = &ProcTable[proc_slot];
   while (currProccess->priority != 0) {
     currProccess = currProccess->next_sibling_ptr;
     proc_slot++;
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

    ProcTable[proc_slot].pid = getpid(); //NOTE: added this

    ProcTable[proc_slot].start_time = (int) get_current_time(); //NOTE: added this

    //TO-DO: fill-in start_time using sys/time. get microseconds
   /* Initialize context for this process, but use launch function pointer for
    * the initial value of the process's program counter (PC)
    */

   ProcTable[proc_slot].stack = (char *) malloc(stacksize);

   context_init(&(ProcTable[proc_slot].state), psr_get(),
                ProcTable[proc_slot].stack,
                ProcTable[proc_slot].stacksize, launch);

   /* for future phase(s) */
   p1_fork(ProcTable[proc_slot].pid);


   Current = &ProcTable[proc_slot];

   return ProcTable[proc_slot].pid;
}


int is_zapped(void) {
  int procPID = getpid();
  proc_ptr walker = &ProcTable[0];
  while (walker != NULL) {
    if (walker->pid == procPID && walker->zapped) {
        return 1;
    }
  }

  return 0;
}

/* zap() does not return until zapped process has quit.
 *  returns -1 if calling process itself was zapped while in zap
 *  returns 0 if the zapped process has already quit
 */

int zap(int pid) {
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


void removeBL(int pid) {
  int found = 0;
  proc_ptr walker = BlockedList;
  proc_ptr prev = BlockedList;
  while (walker != NULL) {
    if (walker->pid == pid) {
      found = 1;
      break;
    }
    prev = walker;
    walker = walker->next_proc_ptr;
  }

  if (found && walker != NULL && prev != NULL) {
      prev->next_proc_ptr = walker->next_proc_ptr;
  }
  else {
    console("could not find process with pid %d in BlockedList.\n", pid);
    halt(1);
  }
}

void insertBL(proc_ptr newProc) {
  if (newProc == NULL) {
    console("insertBL(): newProc is null. Halting..\n");
    halt(1);
  }
  proc_ptr walker = BlockedList;
  proc_ptr prev = BlockedList;

  while (walker != NULL) {
    prev = walker;
    walker = walker->next_proc_ptr;
  }
  prev->next_proc_ptr = newProc;
}
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
  //TO-DO: implement zap() and method to wait until child quits..
  proc_ptr currChild = Current->child_proc_ptr;

  //if there's no children then return -2
  if (currChild == NULL) {
    return -2;
  }
  //check to see if children quit
  else {
    while (currChild->next_proc_ptr != NULL) {
      currChild = currChild->next_sibling_ptr;
    }
    //If there are active children then block parent
    if (!currChild->status) {
      Current->status = *code;
      insertBL(Current);
      Current = currChild;
      dispatcher();
    }
    //otherwise we can simply return id of process
    else {

    }
  }
  //no (unjoined) child has quit(), must wait;

  return code;
} /* join */


/*
 * Make this less redundant later. Two functions below are essentially the same
 *
 */
int check_blocked_list(int pid) {
  proc_ptr walker = BlockedList;
  while (walker != NULL) {
    if (walker->pid == pid) return 1;
    walker = walker->next_proc_ptr;
  }
  return 0;
}

int check_ready_list(int pid) {
  proc_ptr walker = ReadyList;
  while (walker != NULL) {
    if (walker->pid == pid) return 1;
    walker = walker->next_proc_ptr;
  }
  return 0;
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
  int isParent = 0;
  int currPID = Current->pid;

  p1_quit(currPID);

  //check to see if process has children first before trying to terminate it
  if (Current->child_proc_ptr != NULL) {
      proc_ptr currChild = Current->child_proc_ptr;
      int activeChildExists;
      while ((activeChildExists = check_ready_list(currChild->pid)) != 1) {
        currChild = currChild->next_sibling_ptr;
      }
      if (activeChildExists) {
        proc_ptr old = Current;
        Current = Current->child_proc_ptr;
        insertBL(old);
      }

      //no active children so we can terminate it yay
      else {
          Current->status = code;
          Current = Current->next_proc_ptr;
      }

      isParent = 1;
  }

  //Check if parent was blocked due to a join operation
  //first check to find out whose parent this child process belongs to

  if (!isParent) {
    proc_ptr parent;
    proc_ptr walker = &ProcTable[0];
    while (walker != NULL) {
      if (walker->child_proc_ptr != NULL) {
        proc_ptr wChild = walker->child_proc_ptr;
        if (wChild->pid == currPID) {
          parent = walker;
        }
      }
      walker = walker->next_sibling_ptr;
    }

    //now check to see if parent is in readylist to see if its blocked
    if (parent != NULL) {
      int chk_rl = check_ready_list(parent->pid);
      int chk_bl = check_blocked_list(parent->pid);
      if (chk_rl == 0 && chk_bl == 0) {
        removeBL(parent->pid);
        insertRL(parent);
      }
      //otherwise child is orphan which is not supposed to happen..
      else {
        console("child process: %d is an orphan.\n", currPID);
        halt(1);
      }
    }
  }
  //otherwise mark status of process as QUIT
  free(Current->stack);
  Current = ReadyList;
  ReadyList = ReadyList->next_proc_ptr;

  dispatcher();

  return;
} /* quit */


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
   proc_ptr next_process = ReadyList->next_proc_ptr;

   //NOTE: implement check for quantum or if it has been time sliced later..
   //check to see if current process is still highest priority amongst
   //Ready processes
   if (next_process != NULL) {
     if (Current->priority > next_process->priority) {
       insertRL(Current);
       context_switch(Current->state, next_process->state);
       p1_switch(Current->pid, next_process->pid);
     }
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
   while (1)
   {
      check_deadlock();
      waitint();
   }
} /* sentinel */


/* check to determine if deadlock has occurred... */
static void check_deadlock() {
} /* check_deadlock */
    check_io();
    waitint();
/*
 * Disables the interrupts.
 */
void disableInterrupts() {
  /* turn the interrupts OFF iff we are in kernel mode */
  if((PSR_CURRENT_MODE & psr_get()) == 0) {
    //not in kernel mode
    console("Kernel Error: Not in kernel mode, may not disable interrupts\n");
    halt(1);
  } else
    /* We ARE in kernel mode */
    psr_set( psr_get() & ~PSR_CURRENT_INT );
} /* disableInterrupts */
