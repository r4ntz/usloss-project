/* ------------------------------------------------------------------------
   Mark Whitson & Rantz Marion
   Last Edit: 2/2/2021 9:30PM

   phase1.c

   CSCV 452

   TO-DO: implement quit, lookup proper error messages, write empty zap,
   test code. after that add time_slice and use sys.time, add deadlock however
   that works.

   LAST DONE: (1) rough implementation of dispatcher and join. (2) implemented
   getpid() and utilized the returned value inside fork1. (3) decided to call
   dispatcher at end of fork1. may have to change that. i randomly inserted it.
   ------------------------------------------------------------------------ */
#include <stdlib.h>
#include <strings.h>
#include <stdio.h>
#include <phase1.h>
#include "kernel.h"

/* for getpid() */
#include <sys/types.h>
#include <unistd.h>

/* ------------------------- Prototypes ----------------------------------- */
int sentinel (void *);
extern int start1 (char *);
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

/* current process ID */
proc_ptr Current;

/* the next pid to be assigned */
unsigned int next_pid = SENTINELPID;

#define READY 0
#define BLOCKED 1
#define QUIT 2

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

   proc_ptr ReadyList;

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
/* getpid */

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
     halt(1)
   }

   /* Check for valid priority (ADDED) */
   if (priority < LOWEST_PRIORITY || priority > HIGHEST_PRIORITY) {
     console("invalid priority given.\n");
     halt(1)
   }

   /* find an empty slot in the process table */
   //NOTE:ADDED. preemptively linked processes via next_sibling_ptr earlier.
   //searching for process that doesn't have a priority assigned yet. may
   //change this later.
   proc_slot = 0;
   proc_ptr currProccess = &ProcTable[proc_slot]
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

   /* Initialize context for this process, but use launch function pointer for
    * the initial value of the process's program counter (PC)
    */
   context_init(&(ProcTable[proc_slot].state), psr_get(),
                ProcTable[proc_slot].stack,
                ProcTable[proc_slot].stacksize, launch);

   /* for future phase(s) */
   p1_fork(ProcTable[proc_slot].pid);

   //NOTE: not sure where else to call dispatcher for now
   Current = &ProcTable[proc_slot];
   dispatcher();

   return ProcTable[proc_slot].pid;

} /* fork1 */

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
int join(int *code) {
  //TO-DO: implement zap() and method to wait until child quits..
  currChild = Current->child_proc_ptr;
  //if there's no children then return -2
  if (currChild == NULL) {
    *code = -2;
  }
  //check to see if children quit
  else {
    while (currChild != NULL && currChild->status != QUIT) {
      currChild = currChild->next_sibling_ptr;
    }
    //If no child process has quit before join is called, the
    //parent is removed from the ready list and blocked.
    if (currChild->status == QUIT) {
      Current->status = BLOCKED;
      ReadyList = ReadyList->next_proc_ptr; //makes assumption that Current is head of ReadyList..
    }
    else {
      *code = currChild->pid;
    }
  }
  //no (unjoined) child has quit(), must wait;
  return status;
} /* join */


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
   p1_quit(Current->pid);
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

void dispatcher(void) {
   proc_ptr next_process = ReadyList;

   //NOTE: implement check for quantum or if it has been time sliced later..
   if (Current->status == READY) {
      //check to see if current process is still highest priority amongst
      //Ready processes
      if (Current->priority > next_process->priority) {
        insertRL(Current)
        context_switch(Current->state, next_process->state);
        p1_switch(Current->pid, next_process->pid);
      }
   }
   else if (Current->status == BLOCKED) {
     insertRL(Current)
     context_switch(Current->state, next_process->state);
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
