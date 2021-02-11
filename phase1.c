/* ------------------------------------------------------------------------
   Mark Whitson & Rantz Marion
   Last Edit: 2/10/2021 6PM.

   phase1.c

   CSCV 452

   TO-DO: debug for test00, implement clock_handler and enable_interrupts
   when test00 runs fine

   CHANGES:
   -debugged so that the program finally runs (albeit not correctly)
   -overhauled join() and zap()


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
   //may need to indicate that processes havent started idk
   for (i = 0; i < MAXPROC; i++) {
     ProcTable[i].priority = 0; //need to initialize value otherwise undefined behavior
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
  proc_ptr walker;
  //compare pid of each parent and their children
  for (int i=0; i<MAXPROC; i++) {
    walker = &ProcTable[i];
    if (walker->pid == pid) goto FOUND_PROC;
    else if (walker->child_proc_ptr != NULL) {
      proc_ptr child = walker->child_proc_ptr;
      while (child != NULL) {
        if (child->pid == pid) goto FOUND_PROC;
        child = child->next_sibling_ptr;

      }
    }
    FOUND_PROC: break;
  }

  return walker; //handle cases where it points to NULL
}

long int get_current_time(void) {
  struct timeval current_time;
  gettimeofday(&current_time, NULL);
  return current_time.tv_usec;
}

void time_slice(void) {
  return;
}

int read_cur_start_time(void) {
  return Current->start_time;
}

/* rough implementaion for function used in phase2 */
int block_me(int new_status) {
  if (new_status <= 10) {
    console("block_me(): new_status is less than 10 (val: %d)\n", new_status);
    halt(1);
  }
  if (Current->zapped) return -1;
  return 0;
}

void clock_handler(int dev, void * unit){
  return;
}

void removeRL(proc_ptr proc) {
  if (ReadyList == NULL) return;
  proc_ptr walker = ReadyList;
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

   /* Initialize context for this process, but use launch function pointer for
    * the initial value of the process's program counter (PC)
    */

   ProcTable[proc_slot].stack = (char *) malloc(stacksize);

   context_init(&(ProcTable[proc_slot].state), psr_get(),
                ProcTable[proc_slot].stack,
                ProcTable[proc_slot].stacksize, launch);

   /* for future phase(s) */
   p1_fork(ProcTable[proc_slot].pid);

   //NOTE: added 2/9. **current should be swapped when its status changes
   if (Current == NULL) Current = &ProcTable[proc_slot];
   else insertChild(&ProcTable[proc_slot]);

   return ProcTable[proc_slot].pid;
}


int is_zapped(void) {
  int procPID = getpid();
  proc_ptr check_zap = get_proc(procPID);
  if (check_zap != NULL && check_zap->zapped == 1) return 1;
  else return 0;
}

/* zap() does not return until zapped process has quit.
 *  returns -1 if calling process itself was zapped while in zap
 *  returns 0 if the zapped process has already quit
 *
 *  NOTE: think of creating a function that removes procs from readylist
 */

int zap(int pid) {
  proc_ptr zap_this_proc = get_proc(pid);
  proc_ptr walker;
  proc_ptr prev;
  int found = 0;

  if (zap_this_proc != NULL) {
    if (zap_this_proc->zapped == 1) {
      return -1;
    }
    else if (zap_this_proc->status == READY) {
      walker = ReadyList;
      while (walker != NULL) {
        if (walker->pid == pid) {
          found = 1;
          break;
        }
        else {
          prev = walker;
          walker = walker->next_proc_ptr;
        }
      }
    }
    //this means it quit so just return 0
    else return 0;
  }

  else {
    console("process (pid: %d) does not exist.\n");
    halt(1);
  }

  //at this point, this means that the process is ready. now we zap
  if (found) {
    prev->status = 1;
    if (walker != NULL) {
      walker->zapped = 1;
      walker->status = BLOCKED;
      prev->next_proc_ptr = walker->next_proc_ptr;
      dispatcher();
    }
    else prev->next_proc_ptr = NULL;
  }
  return 1;

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
  //TO-DO: implement zap() and method to wait until child quits..
  proc_ptr currChild = Current->child_proc_ptr;

  //if there's no children then return -2
  if (currChild == NULL) {
    return -2;
  }
  //check to see if children quit
  else {
    while (currChild->next_proc_ptr != NULL) {
       if (currChild->status == READY) {
        //"zap does not return until the zapped process has called quit"
        int has_quit = zap(currChild->pid);
        if (has_quit) return currChild->pid;
        else return -1;
      }
      //not sure what to do with blocked processes here yet
      currChild = currChild->next_sibling_ptr;
    }
  }

  return Current->pid;
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
  p1_quit(Current->pid);

  proc_ptr currChild = Current->child_proc_ptr;
  if (currChild != NULL) {
    while (currChild != NULL) {
      if (currChild->status == BLOCKED || currChild->status == READY) {
        console("Process (pid %d) tried to quit with active children.\n", Current->pid);
        halt(1);
      }
      else free(currChild->stack);

      currChild = currChild->next_sibling_ptr;
    }
  }
  //otherwise mark status of process as QUIT
  free(Current->stack);
  if (Current->zapped == 1) Current->zapped = 0;
  Current->status = QUIT;

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
       p1_switch(Current->pid, next_process->pid);
       context_switch(&Current->state, &next_process->state);
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
   while (1) {
      check_deadlock();
      waitint();
   }
   return 1;
} /* sentinel */


/* check to determine if deadlock has occurred... */
static void check_deadlock() {
  /* check_deadlock */
  check_io();
  return;
}


static void enableInterrupts() {
  return;
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
