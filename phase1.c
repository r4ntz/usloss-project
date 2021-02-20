/* ------------------------------------------------------------------------
   Mark Whitson & Rantz Marion
   Last Edit: 2/19/2021 5:45PM.

   phase1.c

   CSCV 452

   TO-DO:
   -got rid of enableInterrupts and disableInterrupts() calls and trying to figure
   out why time_slice() wont stop being called
   -debug and fix what hasn't been accounted for, dump_processes()

   CHANGES:
   -fixed insertRL now we're getting somewhere


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
void clock_handler(int dev, void * unit);
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
void (*int_vec[NUM_INTS])(int dev, void * unit);

/*
 * check if process is in kernel mode and halt if it isnt
 */

void check_mode(void) {
  if ((PSR_CURRENT_MODE & psr_get()) == 0) {
    console("Kernel Error: Not in kernel mode.\n");
    halt(1);
  }
}


/*
 * Enables the interrupts.
 */
void enableInterrupts() {
  //if we're not in kernel mode then halt
  if ((PSR_CURRENT_MODE & psr_get()) == 0) {
    console("Kernel Error: Not in kernel mode, may not enable interrupts\n");
    halt(1);
  }
//if we are in kernel mode, then we can change bits
  else psr_set(psr_get() | PSR_CURRENT_INT);
}
/* enableInterrupts */


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


/* clock_handler()
 * Don't need to invoke this function. USLOSS invokes this
 * every 20 milliseconds (see USLOSS manual). After 4 approx. intervals it will
 * reach the MAXTIME we have set. time_slice() checks this
 */
void clock_handler(int dev, void * unit){
  if (DEBUG && debugflag) console("clock_handler(): started.\n");
  time_slice();
}

/* used for zap */
proc_ptr get_proc(int pid) {
  proc_ptr walker = &ProcTable[pid % MAXPROC];
  if (walker->pid != pid) return NULL;
  else return walker;
}

void init_process(int index) {
    check_mode();

    ProcTable[index].pid = -1;
    ProcTable[index].next_proc_ptr = NO_CURRENT_PROCESS;
    ProcTable[index].next_zappd_ptr = NO_CURRENT_PROCESS;
    ProcTable[index].next_sibling_ptr = NO_CURRENT_PROCESS;
    ProcTable[index].parent_ptr = NO_CURRENT_PROCESS;
    ProcTable[index].zapped = 0;
    ProcTable[index].time_sliced = 0;
    ProcTable[index].num_children = 0;
    ProcTable[index].status = NOT_STARTED;
    ProcTable[index].cpu_time = 0;
    ProcTable[index].start_time = 0;

}

void clear_process(int index) {
  if (DEBUG && debugflag) console("clear_process(): started\n");
  init_process(index);
}

int is_zapped(void) {
  if (DEBUG && debugflag) console("is_zapped(): started.\n");
  if (Current->zapped) return 1;
  else return 0;
}

/* get_current_time()
 * returns length of microseconds since program has started running..
 */
int get_current_time(void) {
  int time_since_boot = sys_clock();
  return time_since_boot;
}

/* insertChild()
 * adds newly created child process to currently running
 * process. add this in fork1() once child is filled w/attributes.
 */
void insertChild(proc_ptr child) {
  init_process(child->pid);

  proc_ptr walker = Current;
  if (walker->child_proc_ptr != NULL) {
    proc_ptr sibling = walker->child_proc_ptr;
    while (sibling->next_sibling_ptr != NULL) {
      sibling = sibling->next_sibling_ptr;
    }
    sibling->next_sibling_ptr = child;
  }
  else walker->child_proc_ptr = child;

  Current->num_children++;
}

/* insertRL()
 * pretty self-explanatory
 * -- just flipped two operators when they compare priority
 */
void insertRL(proc_ptr proc) {
  if(DEBUG && debugflag) console("insertRL(): started. inserting %s() priority: %d\n", proc->name, proc->priority);
  if (ReadyList == NULL) {
    ReadyList = proc;
    return;
  }

  if(DEBUG && debugflag) {
    console("insertRL(): comparing proc: %s() priority: %d,", proc->name, proc->priority);
    console("\tReadyList: %s(), priority: %d\n", ReadyList->name, ReadyList->priority);
  }

  //check if we can insert at front of queue
  if (proc->priority < ReadyList->priority) {
    if(DEBUG && debugflag) console("insertRL(): inserting process pid:%d at front of RL - ", proc->pid);
    proc->next_proc_ptr = ReadyList;
    ReadyList = proc;
    if(DEBUG && debugflag) console("new head: %s() which should == %s\n", ReadyList->name, proc->name);
  }
  //check to see if we can insert anywhere thats not the tail
  else {
    proc_ptr walker = ReadyList;
    while (walker->next_proc_ptr != NULL) {
      if (walker->priority < proc->priority && walker->next_proc_ptr->priority >= proc->priority) {
        if(DEBUG && debugflag)
          console("insertRL(): inserting process %s() into RL.\n", proc->name);
        proc_ptr temp = walker->next_proc_ptr;
        walker->next_proc_ptr = proc;
        proc->next_proc_ptr = temp;
        return;
      }
      walker = walker->next_proc_ptr;
    }
    //if you're here then it needs to go at the tail
    if (walker->next_proc_ptr == NULL) {
      if(DEBUG && debugflag) console("insertRL(): inserting process %s() at tail\n", proc->name);
      walker->next_proc_ptr = proc;
    }
  }
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
int fork1(char *name, int (*f)(char *), char *arg, int stacksize, int priority) {
   check_mode();

   int proc_slot = -1;

   if (DEBUG && debugflag) {
      console("fork1(): creating process %s\n", name);
   }
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


   /* find an empty slot in the table */
    if (ProcTable[1].status == NOT_STARTED) {
      if (DEBUG && debugflag) console("fork1(): sentinel needs to be started.\n");
      proc_slot = 1;
    }
    else {
      for (int i = next_pid; i < (next_pid + MAXPROC); i++) {
        if (ProcTable[i%MAXPROC].status == NOT_STARTED) {
          proc_slot = i%MAXPROC;
          break;
        }
        next_pid++;
      }
    }
    //----
    if (DEBUG && debugflag)
      console("fork1(): process '%s' is now associated with pid: %d\n", name, proc_slot);
    //if there are no slots ready then return -1
    if (proc_slot == -1) return -1;

    /* fill-in entry in process table */
    //name, start_func, arg
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
    else strcpy(ProcTable[proc_slot].start_arg, arg);

    //priority
    if ((priority < MAXPRIORITY || priority > MINPRIORITY) && f != sentinel) {
      if (DEBUG && debugflag)
       console("%s's priority is %d. max: %d, min: %d\n", name, priority, MINPRIORITY, MAXPRIORITY);
      halt(1);
    }
    else {
      ProcTable[proc_slot].priority = priority;
    }

    //pid
    ProcTable[proc_slot].pid = ++next_pid;


   //stack
   ProcTable[proc_slot].stack = (char *) malloc(stacksize);
   ProcTable[proc_slot].stacksize = stacksize;

   /* Initialize context for this process, but use launch function pointer for
    * the initial value of the process's program counter (PC)
    */
   context_init(&(ProcTable[proc_slot].state), psr_get(),
                ProcTable[proc_slot].stack,
                ProcTable[proc_slot].stacksize, launch);

   /* for future phase(s) */
   p1_fork(ProcTable[proc_slot].pid);


   //determine whether to add process as a parent or child
   if (Current != NULL) {
     ProcTable[proc_slot].parent_ptr = Current;
     insertChild(&ProcTable[proc_slot]);
   }

   //insert Readylist and mark as READY
   insertRL(&ProcTable[proc_slot]);
   ProcTable[proc_slot].status = READY;

   //if this isn't the sentinel process then call dispatcher
   if (priority != SENTINELPRIORITY) {
     dispatcher();
   }

   return ProcTable[proc_slot].pid;
}

/* startup()
 *
 * No need to invoke this as USLOSS will do that for us. Equivalent of main()
 */
void startup() {
   if (DEBUG && debugflag) console("startup(): called.\n");
   check_mode();

   int i;      /* loop index */
   int result; /* value returned by call to fork1() */

   /* initialize the process table */
   for (i = 0; i < MAXPROC; i++) {
     init_process(i);
   }

   /* Initialize the Ready list, etc. */
   //if (DEBUG && debugflag)
   //  console("startup(): initializing the Ready & Blocked lists\n");

   /* Initialize the clock interrupt handler */
   int_vec[CLOCK_DEV] = clock_handler;
   enableInterrupts();

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

void removeRL(proc_ptr proc) {
  if (ReadyList == NULL) {
    console("removeRL(): ReadyList is empty.\n");
    halt(1);
  }

  if (proc == ReadyList) {
    ReadyList = proc->next_proc_ptr;
    return;
  }

  proc_ptr walker = ReadyList;
  proc_ptr prev;
  while (walker != NULL) {
    if (proc == walker) break;
    prev = walker;
    walker = walker->next_proc_ptr;
  }
  prev->next_proc_ptr = walker->next_proc_ptr;
  return;
}

//checks to see if process has any time left for execution
void time_slice(void) {
  if (DEBUG && debugflag) console("time_slice(): started\n");
  check_mode();

  int elapsed_time = readtime();
  //this means that the time is up
  if (MAXTIME - elapsed_time <= 0) {
    Current->time_sliced++;
  }
  if (Current->time_sliced == 4) {
    Current->time_sliced = 0;
    removeRL(Current);
    insertRL(Current);
    Current->status = READY;
    dispatcher();
  }
}

//just returns start_time attr which was assigned by get_current_time()
int read_cur_start_time(void) {
  return Current->start_time;
}

/* --------- */


/* rough implementation for function used in phase2
 * NOTE: fix these later...
 */

int block_me(int new_status) {
  if (new_status <= 10) {
    console("block_me(): new_status must be larger than ten. val: %d\n", new_status);
    halt(1);
  }

  if (Current->zapped) return -1;

  check_mode();

  //may have to get rid of three lines below and just call dispatcher()
  //but I need to use new_status in some way not sure how right now..
  Current->status = new_status;
  removeRL(Current);

  dispatcher();

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


/* zap() does not return until zapped process has quit.
 *  returns -1 if calling process itself was zapped while in zap
 *  returns 0 if the zapped process has already quit
 *
 *  NOTE: think of creating a function that removes procs from readylist
 */

int zap(int pid) {
  if (DEBUG && debugflag) console("zap(): starting\n");
  check_mode();

  //Current can't be zapped
  if (Current->pid == pid) {
    if (DEBUG && debugflag) console("zap(): can't zap self\n");
    halt(1);
  }

  //add process associated with pid to zap queue
  proc_ptr this_proc = get_proc(pid % MAXPROC);
  this_proc->zapped = 1;

  if (this_proc->next_zappd_ptr == NULL) {
    this_proc->next_zappd_ptr = Current;
  }
  else {
    proc_ptr walker = this_proc->next_zappd_ptr;
    while (walker->next_zappd_ptr != NULL) {
      walker = walker->next_zappd_ptr;
    }
    walker->next_zappd_ptr = Current;
  }

  //now we just insert our zapped process into Current's zapped process queue
  //and mark Current as blocked
  Current->status = BLOCKED;
  removeRL(Current);
  dispatcher();

  if (Current->zapped) {
    if (DEBUG && debugflag) console("zap(): current process is zapped..\n");
    return -1;
  }

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
void launch() {
  check_mode();
  int result;

  if (DEBUG && debugflag) {
    console("launch(): started\n");
    console("launch(): calling function %s()\n", Current->name);
    console("start_arg: %s\n", Current->start_arg);
  }
  /* Enable interrupts */
  //enableInterrupts(); not sure why that was put here initially

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

  if (DEBUG && debugflag) console("join(): started\n");

  //if there's no children then return -2
  if (Current->num_children == 0) {
    if (DEBUG && debugflag) console("join(): no children!\n");
    return -2;
  }
  //check to see if process was zapped in the join
  if(is_zapped()) {
    return -1;
  }
  //check to see if children quit

  if (DEBUG && debugflag) console("join(): checking for zombie children\n");

  proc_ptr curr_child = Current->child_proc_ptr;

  //if child is a zombie
  if (curr_child->status ==  ZOMBIE) {
    if (DEBUG && debugflag) console("join(): found zombie child\n");
    *code = curr_child->status;
    Current->num_children--;
    if (curr_child->next_zappd_ptr == NULL) {
      curr_child->status = QUIT;
    }
    if (Current->child_proc_ptr->next_sibling_ptr != NULL) {
      Current->child_proc_ptr = Current->child_proc_ptr->next_sibling_ptr;
    }

    return curr_child->pid;
  }

  //otherwise..
  else {
    if (DEBUG && debugflag) console("join(): unable to find a zombie child\n");
    Current->status = BLOCKED;
    removeRL(Current);
    dispatcher();
    if (is_zapped()) {
      return -1;
    }
    *code = Current->child_proc_ptr->status;

    return curr_child->pid;
  }

  //Current->numChildren--;
  return -1;
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

  proc_ptr walker_zappd, walker_child;

  if (is_zapped()) {
    walker_zappd = Current->next_zappd_ptr;
    while (walker_zappd != NULL) {
      proc_ptr temp_proc = &ProcTable[walker_zappd->pid % MAXPROC];
      temp_proc->status = READY;
      insertRL(temp_proc);
      walker_zappd = walker_zappd->next_zappd_ptr;
    }
  }
  //check if process has active children
  if (Current->num_children > 0) {
    walker_child = Current->child_proc_ptr;
    while (walker_child != NULL) {
      if (walker_child->status == ZOMBIE) {
        if (DEBUG && debugflag) console("quit(): error - current process has children.\n");
        halt(1);
      }
      else if (Current->zapped) {
        walker_child = QUIT;
        Current->num_children--;
      }
      walker_child = walker_child->next_sibling_ptr;
    }
  }

  //if quitting process has a parent
  if(Current->parent_ptr != NO_CURRENT_PROCESS) {
    int parent_pid = Current->parent_ptr->pid;
    //(1) check to see if parent is blocked
    if (ProcTable[parent_pid].status == BLOCKED) {
      insertRL(&ProcTable[parent_pid]);
      ProcTable[parent_pid].status = READY;
      //we dont want to run second conditional more than once so lets check
      //to see if they're linked
      if (Current->next_sibling_ptr != NULL) {
        ProcTable[parent_pid].child_proc_ptr = Current->next_sibling_ptr;
      }

      else if (ProcTable[parent_pid].num_children > 1) {
        walker_child = ProcTable[parent_pid].child_proc_ptr;
        proc_ptr prev = NULL;
        while (walker_child != NULL) {
          if (walker_child->pid == Current->pid) {
            prev->next_sibling_ptr = NULL;
          }
          prev = walker_child;
          walker_child = walker_child->next_sibling_ptr;
        }
      }

      else {
          ProcTable[parent_pid].child_proc_ptr = NULL;
      }

      ProcTable[parent_pid].num_children--;
      ProcTable[parent_pid].child_status = code;

    }

    //(2) otherwise just mark it as a zombie
    else Current->status = ZOMBIE;
  }

  Current->status = QUIT;
  p1_quit(Current->pid);
  removeRL(Current);
  free(Current->stack);

  //this is so that the next process can run
  dispatcher();

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
   if (DEBUG && debugflag) console("dispatcher(): started.\n");
   check_mode();

   //clear any processes that have quit from proc table to make searching easier/more clean
   if (DEBUG && debugflag) console("dispatcher(): clearing processes that have quit.\n");
   for (int i=0; i<MAXPROC; i++) {
     //found parent thats quit
     if (ProcTable[i].status == QUIT) clear_process(i);
     //found child thats quit
     else if (ProcTable[i].status == ZOMBIE) {
      if(ProcTable[i].parent_ptr->pid == -1) clear_process(i);
     }
   }

   if (DEBUG && debugflag) console("dispatcher(): context switching - ");


   proc_ptr old_process;

   if (Current == NULL) {
     old_process = NULL;
     Current = ReadyList;
     Current->start_time = get_current_time();
     Current->status = RUNNING;
     if (DEBUG && debugflag) console("starting %s()\n", Current->name);
     context_switch(NULL, &Current->state);
   }
   else {
     old_process = Current;
     Current = ReadyList;
     Current->start_time = get_current_time();
     Current->status = RUNNING;

     if (old_process->pid != -1) {
       int time_now = sys_clock();
       int cpu_time = (time_now - old_process->start_time)/1000;
       old_process->cpu_time = cpu_time;
     }
     else old_process->cpu_time = 0;

    p1_switch(old_process->pid, Current->pid);
    if (DEBUG && debugflag) console("old: %s()\tnew: %s()\n", old_process->name, Current->name );
    context_switch(&old_process->state, &Current->state);
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
  if (DEBUG && debugflag) console("check_deadlock(): called.\n");

  if (ReadyList->next_proc_ptr == NULL) {
    if (DEBUG && debugflag) console("check_deadlock(): no processes remaining\n");
  }
  else if (ReadyList->priority == SENTINELPRIORITY) {
    if (DEBUG && debugflag)
      console("check_deadlock(): there are processes still remaining\n");
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
