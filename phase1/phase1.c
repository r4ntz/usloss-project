/* ------------------------------------------------------------------------
	Mark Whitson & Rantz Marion
	Last Edit: 2/25/2021 11:30PM.

	phase1.c

	CSCV 452

	-Issues with test case 5 and 23. Haven't tested past 23 yet.
	 --Case 5: Looks like an issue with clock_handler im not sure. It's not
	 		being invoked by USLOSS even though its defined.
	 --Case 23: Issues with zombie children in quit() need to investigate.

------------------------------------------------------------------------ */

#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <stdio.h>
#include <phase1.h>
#include "kernel.h"

/* ------------------------- Prototypes ----------------------------------- */
int sentinel (char *); //from (void *) to (char *dummy)
extern int start1 (char *);
extern int check_io();
extern void (*int_vec[NUM_INTS])(int dev, void * unit);
extern void dump_processes(void);
void dispatcher(void);
void launch();
void clock_handler(int dev, void * unit);
void check_mode(void);
int getpid(void);
int zap(int);
int is_zapped(void);
int get_current_time(void);
void removeChild(proc_ptr);
void insertChild(proc_ptr);
void insertRL(proc_ptr);
void removeRL(proc_ptr);
void time_slice(void);
int block_me(int);
int unblock_proc(int);
void enableInterrupts();
void disableInterrupts();
static void check_deadlock();
void init_process(int);

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

/* ------------------------------------------------------------------------ */



/* ------------------------------------------------------------------------
   Name - check_mode
   Purpose - checks to see if we're currently in kernel mode otherwise halt
------------------------------------------------------------------------ */
void check_mode(void)
{
	if ((PSR_CURRENT_MODE & psr_get()) == 0)
	{
		console("Kernel Error: Not in kernel mode.\n");
		halt(1);
	}
}



/* ------------------------------------------------------------------------
 Name - enableInterrupts
 ------------------------------------------------------------------------ */
void enableInterrupts()
{
//if we're not in kernel mode then halt
	check_mode();
	//if we are in kernel mode, then we can change bits
	psr_set(psr_get() | PSR_CURRENT_INT);
}


/* ------------------------------------------------------------------------
 Name - disableInterrupts
 ------------------------------------------------------------------------ */
void disableInterrupts()
{
	//if we're not in kernel mode then halt
	check_mode();
	/* turn the interrupts OFF iff we are in kernel mode */
	psr_set(psr_get() & ~PSR_CURRENT_INT);

}

/* ------------------------------------------------------------------------
Name - clock_handler
Purpose - Don't need to invoke this function. USLOSS invokes this
	every 20 ms per USLOSS manual - After 4 approx. intervals it will hit MAXTIME
	time_slice() checks this
 ------------------------------------------------------------------------ */

void clock_handler(int dev, void * unit)
{
	console("Started!\n");
	if (DEBUG && debugflag) console("clock_handler(): started.\n");
	time_slice();
}

/* Used for zap */
proc_ptr get_proc(int pid)
{
  proc_ptr walker = &ProcTable[pid%MAXPROC];
	if (walker->pid != pid) return NULL;

	else return walker;
}


/* ------------------------------------------------------------------------
   Name - init_process
   Purpose - initializes attributes for process or clears them in case of
	 quit to make room for more processes
   ------------------------------------------------------------------------ */
void init_process(int index)
{
    ProcTable[index].pid = -1;
		ProcTable[index].name[0] = '\0';
		ProcTable[index].priority = 0;
		ProcTable[index].start_arg[0] = '\0';
    ProcTable[index].next_proc_ptr = NO_CURRENT_PROCESS;
    ProcTable[index].next_zappd_ptr = NO_CURRENT_PROCESS;
		ProcTable[index].child_proc_ptr = NO_CURRENT_PROCESS;
    ProcTable[index].next_sibling_ptr = NO_CURRENT_PROCESS;
    ProcTable[index].parent_ptr = NO_CURRENT_PROCESS;
    ProcTable[index].zapped = 0;
    ProcTable[index].time_sliced = 0;
    ProcTable[index].num_children = 0;
    ProcTable[index].status = EMPTY;
    ProcTable[index].start_time = -1;
		ProcTable[index].cpu_time = -1;
		#ifdef __APPLE__
			free(ProcTable[index].stack);
		#endif
		ProcTable[index].stack = NULL;
		ProcTable[index].child_status = 0;
}

/* ------------------------------------------------------------------------
   Name - getpid
   Purpose - gets pid of current process
   ------------------------------------------------------------------------ */
int getpid(void) {
	return Current->pid;
}

/* ------------------------------------------------------------------------
   Name - is_zapped
   Purpose - checks to see if current process was zapped. return 1 otherwise 0
   ------------------------------------------------------------------------ */
int is_zapped(void)
{
	if (DEBUG && debugflag) console("is_zapped(): started.\n");
	if (Current->zapped) return 1;
	else return 0;
}

/* ------------------------------------------------------------------------
   Name - get_current_time
   Purpose - gets the curent time by calling USLOSS function sys_clock
   ------------------------------------------------------------------------ */
int get_current_time(void)
{
	int time_since_boot = sys_clock();
	return time_since_boot;
}

/* ------------------------------------------------------------------------
   Name - removeChild
   Purpose - removes child from queue of its respective parent and maintains
	 links
   ------------------------------------------------------------------------ */
void removeChild(proc_ptr child) {
	if (DEBUG && debugflag)
	 console("removeChild(): removing %s pid: %d\n", child->name, child->pid);
	proc_ptr parent = child->parent_ptr;
	//check if child is eldest sibling
	if (parent->num_children == 0) console("suck my cock\n");
	if (parent->child_proc_ptr->pid == child->pid) {
		proc_ptr new_head = child->next_sibling_ptr;
		parent->child_proc_ptr = new_head;
	}
	//otherwise locate and remove from queue
	else if (parent->num_children > 1) {
		proc_ptr walker = parent->child_proc_ptr;
		proc_ptr prev = NO_CURRENT_PROCESS;
		while (walker != NO_CURRENT_PROCESS) {
			if (walker->pid == child->pid) {
				prev->next_sibling_ptr = walker->next_sibling_ptr;
				break;
			}
			prev = walker;
			walker = walker->next_sibling_ptr;
		}
	}
	parent->num_children--;
}

/* ------------------------------------------------------------------------
   Name - insertChild
   Purpose - finds location to insert child of respective parent
   ------------------------------------------------------------------------ */
void insertChild(proc_ptr child) {
	if (DEBUG && debugflag)
		console("insertChild(): inserting %s pid: %d\n", child->name, child->pid);

	if (Current->child_proc_ptr != NO_CURRENT_PROCESS) {
		proc_ptr sibling = Current->child_proc_ptr;
		//console("child of %s is %s pid: %s\n", Current>name, sibling->name, sibling->pid);
		while (sibling->next_sibling_ptr != NULL) {
			sibling = sibling->next_sibling_ptr;
		}
		sibling->next_sibling_ptr = child;
	}
	else Current->child_proc_ptr = child;
	Current->num_children++;
}

/* ------------------------------------------------------------------------
   Name - insertRL
   Purpose - Pretty self-explanatory. Inserts based on priority of process
   ------------------------------------------------------------------------ */
void insertRL(proc_ptr proc) {
  if(DEBUG && debugflag) console("insertRL(): started. inserting %s() pid: %d\n", proc->name, proc->pid);
  if (ReadyList == NULL) {
    ReadyList = proc;
    return;
  }

  if(DEBUG && debugflag) {
    console("insertRL(): comparing proc: %s(), pid: %d, priority: %d,", proc->name, proc->pid, proc->priority);
    console("\tReadyList: %s(), priority: %d\n", ReadyList->name, ReadyList->priority);
  }

  //check if we can insert at front of queue
  if (proc->priority < ReadyList->priority) {
    if(DEBUG && debugflag) console("insertRL(): inserting process (%s) pid:%d at front of RL\n", proc->name, proc->pid);
    proc->next_proc_ptr = ReadyList;
    ReadyList = proc;
  }
  //check to see if we can insert anywhere thats not the tail
  else {
    proc_ptr walker = ReadyList;
    while (walker->next_proc_ptr != NULL) {
			//if (walker->next_proc_ptr->priority == proc->priority)
			//	walker = walker->next_proc_ptr;
      if (walker->priority <= proc->priority && walker->next_proc_ptr->priority > proc->priority) {
        if(DEBUG && debugflag)
          console("insertRL(): inserting process %s() into RL after %s() pid: %d\n", proc->name, walker->name, walker->pid);
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
   ------------------------------------------------------------------------ */
int fork1(char *name, int (*f)(char *), char *arg, int stacksize, int priority) {
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
     if (DEBUG && debugflag) console("stacksize is too small.\n");
     return -2;
   }

	 disableInterrupts();

   /* find an empty slot in the table */
    if (ProcTable[1].status == EMPTY) {
      if (DEBUG && debugflag) console("fork1(): sentinel needs to be started.\n");
      proc_slot = 1;
    }
    else {
			int max_val = next_pid + MAXPROC;
      for (int i = next_pid; i < max_val; ++i) {
        if (ProcTable[i%MAXPROC].status == EMPTY) {
          proc_slot = i%MAXPROC;
          break;
        }
				else next_pid++;
      }
    }

		//to avoid issue where 50 is forked right after it quits and new process is
		//initialized
		int new_pid = next_pid;
		next_pid++;

    //----
    if (DEBUG && debugflag)
			console("fork1(): process '%s' is now associated with pid: %d\n", name, new_pid);

    /* if there are no slots ready then return -1 */
    if (proc_slot == -1) return -1;

    /* validate fill-in name, start_func, arg in process table */

    /* Validate and set name*/
    if ( strlen(name) >= (MAXNAME - 1) ) {
      console("fork1(): Process name is too long.  Halting...\n");
      halt(1);
    }
	else {
    strcpy(ProcTable[proc_slot].name, name);
    ProcTable[proc_slot].start_func = f;
    }

	/* validate argument len*/
	if ( arg == NULL ) ProcTable[proc_slot].start_arg[0] = '\0';
	else if ( strlen(arg) >= (MAXARG - 1) ) {
      console("fork1(): argument too long.  Halting...\n");
      halt(1);
    }
    else strcpy(ProcTable[proc_slot].start_arg, arg);

    /* validate priority */
    if ((priority < MAXPRIORITY || priority > MINPRIORITY) && f != sentinel) {
      console("start1(): couldn't fork a child -- invalid priority\n");
      halt(1);
    }
    else {
      ProcTable[proc_slot].priority = priority;
    }

    /* set pid */
    ProcTable[proc_slot].pid = new_pid;

   /* generate stack */
   ProcTable[proc_slot].stack = (char *) malloc(stacksize);
   ProcTable[proc_slot].stacksize = stacksize;

   /* Initialize context for this process, but use launch function pointer for
    * the initial value of the process's program counter (PC)
    */

   context_init(&(ProcTable[proc_slot].state), psr_get(),
                ProcTable[proc_slot].stack,
                ProcTable[proc_slot].stacksize, launch);
   /* for future phase(s) */
   //p1_fork(ProcTable[proc_slot].pid);


   /* determine to add process as parent or child */
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

   return new_pid;
}



/* ------------------------------------------------------------------------
   Name - startup
   Purpose - Initializes process lists and clock interrupt vector.
	     Start up sentinel process and the test process.
   ----------------------------------------------------------------------- */
void startup() {
   if (DEBUG && debugflag) console("startup(): called.\n");

   int i;      /* loop index */
   int result; /* value returned by call to fork1() */

   /* initialize the process table */
   for (i = 0; i < MAXPROC; i++) {
     init_process(i);
   }

   /* Initialize the Ready list, etc. */

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
}


/* ------------------------------------------------------------------------
   Name - finish
   Purpose - Required by USLOSS
   ----------------------------------------------------------------------- */
void finish() {
  if (DEBUG && debugflag)
    console("in finish...\n");
} /* finish */


/* ------------------------------------------------------------------------
   Name - readtime
   Purpose - Gets start time of current process and subtracts it by current
	 time. Returns the difference
   ------------------------------------------------------------------------ */
int readtime(void) {
  int curr_time_since_boot = sys_clock();
  int curr_time = read_cur_start_time();
  //we divide by 1000 since we need to convert to millseconds
  int cpu_time = (curr_time - curr_time_since_boot);

  return cpu_time;
}


/* ------------------------------------------------------------------------
   Name - removeRL
   Purpose - pretty self-explanatory. Removes process from queue while
	 maintaining links
   ------------------------------------------------------------------------ */
void removeRL(proc_ptr proc) {
	if (DEBUG && debugflag)
		console("removeRL(): removing %s() pid: %d from ReadyList\n", proc->name, proc->pid);
  if (ReadyList == NULL) {
    console("removeRL(): ReadyList is empty.\n");
    halt(1);
  }

  if (proc == ReadyList) {
		if (DEBUG && debugflag)
			console("removeRL: %s() (pid: %d) happens to be head of RL. Making %s() (pid: %d) new head\n", proc->name, proc->pid, proc->next_proc_ptr->name, proc->next_proc_ptr->pid);
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

/* checks to see if process has any time left for execution */
void time_slice(void) {
  if (DEBUG && debugflag) console("time_slice(): started\n");

  int elapsed_time = readtime();
  console("elapsed time: %d\n", elapsed_time);
  //this means that the time is up
  if (MAXTIME - elapsed_time <= 0) {
    Current->time_sliced++;
  }
  if (Current->time_sliced == 4) {
    Current->time_sliced = 0;
		Current->priority--;
		removeRL(Current);
		insertRL(Current);
    dispatcher();
  }
}

//just returns start_time attr which was assigned by get_current_time()
int read_cur_start_time(void) {
  return Current->start_time;
}

/* --------- */




/* ------------------------------------------------------------------------
   Name - block_me
   Purpose - sets new status on Current process, removes from RL, and calls
	 dispatcher
   ------------------------------------------------------------------------ */
int block_me(int new_status) {
	disableInterrupts();
	if (new_status <= 10) {
    console("block_me(): new_status must be larger than ten. val: %d\n", new_status);
    halt(1);
  }

  if (Current->zapped) return -1;

  Current->status = new_status;
  removeRL(Current);
  dispatcher();

	if (is_zapped()) return -1;
	else return 0;
}



/* ------------------------------------------------------------------------
   Name - unblock_proc
   Purpose - sets status changed by block_me back to READY, inserts into
	 RL and calls dispatcher
   ------------------------------------------------------------------------ */
int unblock_proc(int pid){
	proc_ptr unblock_this = get_proc(pid);

  if (pid == getpid() || unblock_this->pid != pid || unblock_this->status < 11) {
    return -2;
  }

	if (is_zapped()) return -1;

	unblock_this->status = READY;
	insertRL(unblock_this);
	dispatcher();

	return 0;
}



/* ------------------------------------------------------------------------
   Name - zap
   Purpose - zapblocks current process and removes from RL
   ------------------------------------------------------------------------ */
int zap(int pid) {
  if (DEBUG && debugflag) console("zap(): started.\n");

  //Current can't be zapped ---
  //when it gets zapped in dispatcher(), Current changes and becomes old_process
  if (pid == getpid()) {
    console("zap(): process %d tried to zap itself. Halting...\n", pid);
    halt(1);
  }

	disableInterrupts();

  //add process associated with pid to zap queue
  proc_ptr zap_this = get_proc(pid);

  if (DEBUG && debugflag) console("zap(): going to zap %s()\n", zap_this->name);
  zap_this->zapped = 1;
  if (Current->next_zappd_ptr == NULL) {
    Current->next_zappd_ptr = zap_this;
  }
  else {
    proc_ptr walker = Current->next_zappd_ptr;
    while (walker->next_zappd_ptr != NULL) {
      walker = walker->next_zappd_ptr;
    }
    walker->next_zappd_ptr = zap_this;
  }

  //no need to remove from RL because quit will do this on each zapped process
	Current->status = ZAP_BLOCK;
	removeRL(Current);
	dispatcher();

	if (is_zapped()) return -1;
  else return 0;

}


/* ------------------------------------------------------------------------
   Name - launch
   Purpose - Dummy function to enable interrupts and launch a given process
             upon startup.
   ------------------------------------------------------------------------ */
void launch() {
  int result;

  if (DEBUG && debugflag) {
    console("launch(): started\n");
    console("launch(): calling function %s()\n", Current->name);
    console("start_arg: %s\n", Current->start_arg);
  }
  /* Enable interrupts */
  enableInterrupts(); //not sure why that was put here initially

  /* Call the function passed to fork1, and capture its return value */
  result = Current->start_func(Current->start_arg);

  if (DEBUG && debugflag)
    console("launch(): process %s() returned to launch, result: %d\n", Current->name, result);

  quit(result);

}



/* ------------------------------------------------------------------------
   Name - join
   Purpose - Wait for a child process (if one has been forked) to quit.  If
             one has already quit, don't wait.
   ------------------------------------------------------------------------ */
int join(int * code) {
	disableInterrupts();

  if (DEBUG && debugflag) console("join(): started. current: %s, pid: %d\n", Current->name, Current->pid);

  //if there's no children then return -2
  if (Current->num_children == 0) {
    if (DEBUG && debugflag) console("join(): no children!\n");
		*code = 0;
    return -2;
  }
  //check to see if process was zapped in the join
  if(is_zapped()) {
    return -1;
  }


	/*check to see if children quit */
  if (DEBUG && debugflag) console("join(): checking for zombie children\n");

  proc_ptr curr_child = Current->child_proc_ptr;

	while(curr_child != NULL) {
  	if (curr_child->status == ZOMBIE) {
    	console("join(): found zombie child\n");
			curr_child->status = QUIT;
			*code = curr_child->status;
			int child_pid = curr_child->pid;
			removeChild(curr_child);
			init_process(curr_child->pid % MAXPROC);
    	return child_pid;
  	}
		else if (curr_child->status == ZAP_BLOCK) {
			curr_child->status = READY;
			insertRL(curr_child);
			dispatcher();
		}
		curr_child = curr_child->next_sibling_ptr;
	}

  //otherwise..
  if (DEBUG && debugflag) {
    console("join(): children havent quit yet, ");
    console("setting status of parent (%s) to JOIN_BLOCK\n", Current->name);
		console("join(): %s's kid: name- %s status- %d\n", Current->name, Current->child_proc_ptr->name);
  }

	Current->status = JOIN_BLOCK;

  removeRL(Current);
	int child_pid = Current->child_proc_ptr->pid;
  if (DEBUG && debugflag)
		console("join(): process (%s) is calling dispatcher.\n", Current->name);

	dispatcher();

	//check if new Current process is zapped. Fixes a test case
	if(is_zapped()) {
    return -1;
  }

	*code = Current->child_status;
  return child_pid;

}



/* ------------------------------------------------------------------------
   Name - quit
   Purpose - Stops the child process and notifies the parent of the death by
             putting child quit info on the parents child completion code
             list.
   ------------------------------------------------------------------------ */
void quit(int code) {
  if (DEBUG && debugflag) console("quit(): started process (%s) pid: %d\n", Current->name, Current->pid);
	disableInterrupts();

  proc_ptr walker_zappd, walker_child;

  //if its zapped then that must mean that its parent is ZAP_BLOCK
  if (is_zapped()) {
    if (DEBUG && debugflag) console("quit(): is_zapped() returns TRUE\n");
    walker_zappd = Current->next_zappd_ptr;
    while (walker_zappd != NULL) {
			walker_zappd->status = READY;
			insertRL(walker_zappd);
      walker_zappd = walker_zappd->next_zappd_ptr;
    }
  }

  //check if process has active children
  if (Current->num_children > 0) {
    walker_child = Current->child_proc_ptr;
    while (Current->num_children > 0) {
      if (walker_child->status == READY) {
        console("quit(): process %d quit with active children\n", Current->pid);
        halt(1);
      }
      else if (walker_child->zapped) {
				walker_child = QUIT;
				Current->num_children--;
				dispatcher();
      }
      walker_child = Current->child_proc_ptr;
    }
  }

	Current->status = QUIT;
	removeRL(Current);


  //if quitting process has a parent
  if(Current->parent_ptr != NO_CURRENT_PROCESS) {
    if (DEBUG && debugflag) {
      console("quit(): process confirmed to be a child, ");
      console("checking if parent is blocked.\n");
    }

    proc_ptr parent = Current->parent_ptr;
    //(1) check to see if parent is blocked
    if (parent->status == JOIN_BLOCK || parent->status == ZAP_BLOCK) {
      if (DEBUG && debugflag) console("quit(): %s's parent is blocked.\n", Current->name);
			parent->status = READY;
			insertRL(parent);
			removeChild(Current);
			init_process(Current->pid % MAXPROC);
			parent->child_status = code;
		}
    //(2) otherwise just mark it as a zombie
    else {
      if (DEBUG && debugflag)
        console("quit(): process (%s) was not blocked. turning into zombie\n", Current->name);
      Current->status = ZOMBIE;
    }
  }

  if (DEBUG && debugflag) console("quit(): process (%s) is calling dispatcher()\n", Current->name);
  dispatcher();
	//may have to disable interrupts here again

}



/* ------------------------------------------------------------------------
   Name - dispatcher
   Purpose - dispatches ready processes.  The process with the highest
             priority (the first on the ready list) is scheduled to
             run.  The old process is swapped out and the new process
             swapped in.
   ----------------------------------------------------------------------- */

void dispatcher(void) {
   if (DEBUG && debugflag) console("dispatcher(): started.\n");
   if (DEBUG && debugflag) console("dispatcher(): context switching.\n");


   proc_ptr old_process;

   if (Current == NULL) {
     old_process = NULL;
     Current = ReadyList;
     Current->start_time = get_current_time();
     Current->status = RUNNING;
     if (DEBUG && debugflag) console("dispatcher(): starting %s()\n", Current->name);
		 enableInterrupts();
     context_switch(NULL, &Current->state);
   }

   else  {
  	old_process = Current;
    Current = ReadyList;
		if (DEBUG && debugflag)
			console("dispatcher(): pid of new Current process (%s): %d\n", Current->name, Current->pid);
  }

  Current->start_time = get_current_time();
  Current->status = RUNNING;

	if (old_process->pid != -1) {
  	int time_now = sys_clock();
    int cpu_time = (time_now - old_process->start_time)/1000;
    old_process->cpu_time = cpu_time;
	}

	//p1_switch(old_process->pid, Current->pid);
  if (DEBUG && debugflag)
		console("dispatcher()- old: %s(), pid: %d\tnew: %s(), pid: %d\n", old_process->name, old_process->pid, Current->name, Current->pid);
	enableInterrupts();
  context_switch(&old_process->state, &Current->state);
}



/* ------------------------------------------------------------------------
   Name - sentinel
   Purpose - The purpose of the sentinel routine is two-fold.  One
             responsibility is to keep the system going when all other
	     processes are blocked.  The other is to detect and report
	     simple deadlock states.
   ----------------------------------------------------------------------- */
int sentinel (char * dummy) {
  if (DEBUG && debugflag) console("sentinel(): called\n");

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
  int num_processes = 1;

  if (DEBUG && debugflag) console("check_deadlock(): called. process: %s\n", Current->name);
  for (int i=2; i<MAXPROC; i++) {
    if (ProcTable[i].status != QUIT && ProcTable[i].status != EMPTY) {
      num_processes++;
    }
  }

  if (num_processes > 1) {
    console("check_deadlock(): num_proc = %d\n", num_processes);
		console("check_deadlock(): processes still present. Halting..\n");
    halt(1);
  }
  else {
    console("All processes completed\n");
    halt(0);
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
----------------------------------------------------------------------- */

void dump_processes(void) {
  if (DEBUG && debugflag) {
   		console("dump_processes(void): Outputting all proc info\n\n");
  }

  //output running procs based on a valid PID
	console("PID\t\tPRIORITY\tSTATUS\t\t# KIDS\t\tCPU TIME\tNAME\n");
  for (int i=0; i < MAXPROC; i++){
   	console("%d\t\t",ProcTable[i].pid);
   	console("%d\t\t",ProcTable[i].priority);
   	if(ProcTable[i].status == QUIT) console("QUIT\t\t");
   	else if(ProcTable[i].status == ZAP_BLOCK) console("ZAP_BLOCK\t");
   	else if(ProcTable[i].status == READY) console("READY\t\t");
   	else if(ProcTable[i].status == RUNNING) console("RUNNING\t\t");
   	else if(ProcTable[i].status == ZOMBIE) console("ZOMBIE\t\t");
   	else if(ProcTable[i].status == JOIN_BLOCK) console("JOIN_BLOCK\t");
    else if (ProcTable[i].status == EMPTY) console("EMPTY\t\t");
   	else {
      console("%d\t\t", ProcTable[i].status);
   	}
   	console("%d\t\t", ProcTable[i].num_children);
   	console("%dms\t\t",ProcTable[i].cpu_time);
		console("%s\n",ProcTable[i].name);
  }
	console("\n");
}
