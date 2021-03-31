/* ------------------------------------------------------------------------
	phase2.c

	University of Arizona South
	Computer Science 452


	Rantz Marion & Mark Whitson

------------------------------------------------------------------------ */


/* ------------------------- Includes ----------------------------------- */

#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <phase1.h>
#include <phase2.h>
#include <usloss.h>
#include "message.h"


/* ------------------------- Prototypes ----------------------------------- */

//Phase 2 Prototypes

int start1 (char *);
int MboxCreate(int, int);
int MboxSend(int, void *, int);
int MboxCondSend(int, void *, int);
int MboxReceive(int, void *, int);
int MboxCondReceive(int, void *, int);
int MboxRelease(int);
int MboxCheck (int, void *, int);
void clock_handler2(int, void *);
void disk_handler(int, void *);
void term_handler(int, void *);
int check_io(void);
void check_kernel_mode(char *);
void enableInterrupts(void);
void disableInterrupts(void);
void add_process(int, void *, int);
slot_ptr set_slot(int, int, void *, int);
int insert_slot(slot_ptr, mbox_ptr);
int find_empty_slot(void);
void nullsys(sysargs *);
extern int start2 (char *);
extern void (*int_vec[NUM_INTS])(int dev, void * unit);

//Phase 1 functions
extern int fork1(char *name, int (*func)(char *), char *arg, int stacksize, int priority);
extern int join(int *status);
extern void quit(int status);
extern int zap(int pid);
extern int is_zapped(void);
extern int getpid(void);
extern void dump_processes(void);
extern int block_me(int block_status);
extern int unblock_proc(int pid);
extern int read_cur_start_time(void);
extern void time_slice(void);

/* -------------------------- Globals ------------------------------------- */

int debugflag2 = 1;
int clock_intervals = 0;

/* the mail boxes */
mailbox MailBoxTable[MAXMBOX];
mail_slot SlotTable[MAXSLOTS];

/* proc table */
mbox_proc MboxProcTable[MAXPROC];

/* system call vector */
void (*sys_vec[MAXSYSCALLS])(sysargs * args);

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
   Name - nullsys
   Purpose - To handle invalid sys calls
   Parameters - args
   Returns - Nothing
   Side Effects - Halts
   ----------------------------------------------------------------------- */
void nullsys(sysargs * args)
{
    console("nullsys(): Invalid syscall %d. Halting...\n", args->number);
    halt(1);
} /* nullsys */



/* ------------------------------------------------------------------------
   Name - enableInterrupts
   Purpose - Self-explanatory. Basically changes bits
   Parameters - dev, unit
   Returns - Nothing
   Side Effects - None
   ----------------------------------------------------------------------- */
void disableInterrupts()
{
	//console("%d | %d = %d\n", psr_get(), PSR_CURRENT_INT, psr_get() | PSR_CURRENT_INT);

	//PSR_CURRENT_INT is 0x2
	psr_set(psr_get() | PSR_CURRENT_INT);
}


/* ------------------------------------------------------------------------
   Name - disableInterrupts
   Purpose - Self-explanatory. Basically changes bits
   Parameters - None
   Returns - Nothing
   Side Effects - None
   ----------------------------------------------------------------------- */
void enableInterrupts()
{
	//console("%d & ~%d = %d\n", psr_get(), ~PSR_CURRENT_INT, psr_get() & ~PSR_CURRENT_INT);

	psr_set(psr_get() & ~PSR_CURRENT_INT);
}


/* ------------------------------------------------------------------------
   Name - check_io
   Purpose - We check to see if there are any non-zero slot mb's that are active
   Parameters - dev, unit
   Returns - Nothing
   Side Effects - None
   ----------------------------------------------------------------------- */
int check_io()
{
	for (int i=0; i < 7; i++)
	{
		if (MailBoxTable[i].block_receive_queue != NULL) return 1;
	}
	return 0;
} /* check_io */


/* ------------------------------------------------------------------------
   Name - clock_handler2
   Purpose - Conditionally send contents of status register to mailbox
   Parameters - dev, unit
   Returns - Nothing
   Side Effects - None
   ----------------------------------------------------------------------- */
void clock_handler2(int dev, void * unit)
{
	if (DEBUG2 && debugflag2) console("clock_handler2(): started.\n");
	check_kernel_mode("clock_handler2");
	disableInterrupts();

	/* check to make sure right values were passed */
	if (dev != CLOCK_INT)
	{
		if (DEBUG2 && debugflag2)
		{
			console("clock_handler2(): wrong device\n");
		}
		halt(1);
	}

	/* otherwise conditionally send contents of status register */
	int status;

	if (++clock_intervals >= 5)
	{
		int ret = device_input(dev, 0, &status);
		if (ret == DEV_INVALID)
		{
			if (DEBUG2 && debugflag2)
			{
				console("clock_handler2(): dev or unit is invalid\n");
			}
			halt(1);
		}

		MboxCondSend(0, &status, sizeof(int));
		clock_intervals = 0;
	}

	time_slice();
	enableInterrupts();

} /* clock_handler2 */

/* ------------------------------------------------------------------------
   Name - disk_handler
   Purpose - Pretty much same as clock_handler2 minus the time_slice
   Parameters - dev, unit
   Returns - Nothing
   Side Effects - None
   ----------------------------------------------------------------------- */
void disk_handler(int dev, void * unit)
{
	if (DEBUG2 && debugflag2) console("disk_handler(): started.\n");
	check_kernel_mode("disk_handler");
	disableInterrupts();

	if (dev != DISK_DEV)
	{
		if (DEBUG2 && debugflag2)
		{
			console("disk_handler(): wrong device\n");
		}
		halt(1);
	}

	int status;
	int mbox_id = ((long) unit) + 1;
	int ret = device_input(dev, (long) unit, &status);
	if (ret == DEV_INVALID)
	{
		if (DEBUG2 && debugflag2)
		{
			console("disk_handler(): dev or unit is invalid\n");
		}
		halt(1);
	}
	MboxCondSend(mbox_id, &status, sizeof(int));
	enableInterrupts();
} /* disk_handler */


/* ------------------------------------------------------------------------
   Name - term_handler
   Purpose - Pretty much same as clock_handler2 minus the time_slice
   Parameters - dev, unit
   Returns - Nothing
   Side Effects - None
   ----------------------------------------------------------------------- */
void term_handler(int dev, void * unit)
{
	if (DEBUG2 && debugflag2) console("term_handler(): started.\n");
	check_kernel_mode("term_handler");
	disableInterrupts();

	if (dev != TERM_DEV)
	{
		if (DEBUG2 && debugflag2)
		{
			console("term_handler(): wrong device\n");
		}
		halt(1);
	}

	int status;
	int mbox_id = (long) unit + 3;
	int ret = device_input(dev, (long) unit, &status);
	if (ret == DEV_INVALID)
	{
		if (DEBUG2 && debugflag2)
		{
			console("term_handler(): dev or unit is invalid\n");
		}
		halt(1);
	}
	MboxCondSend(mbox_id, &status, sizeof(int));
	enableInterrupts();
} /* term_handler */


/* ------------------------------------------------------------------------
   Name - syscall_handler
   Purpose - Part of interrupt vector
   Parameters - dev, unit
   Returns - Nothing
   Side Effects - None
   ----------------------------------------------------------------------- */
void syscall_handler(int dev, void * unit)
{
	if (DEBUG2 && debugflag2) console("syscall_handler(): called.\n");
	check_kernel_mode("syscall_handler");
	disableInterrupts();

	sysargs * args = unit;
	int syscall = args->number;

	if (dev != SYSCALL_INT || syscall < 0 || syscall >= MAXSYSCALLS)
	{
		console("syscall_handler(): dev or syscall #%d is wrong.\n", syscall);
		halt(1);
	}

	(*sys_vec[syscall])(args);
	enableInterrupts();
} /* syscall_handler() */


/* ------------------------------------------------------------------------
   Name - init_mailbox
   Purpose - Sets default values for mailbox. Called by start1
   Parameters - mailbox id used to index into it
   Returns - Nothing
   Side Effects - Erases any previously set attributes if called again
   ----------------------------------------------------------------------- */
void init_mailbox(int id)
{
  MailBoxTable[id].mbox_id = id;
  MailBoxTable[id].status = EMPTY;
  MailBoxTable[id].num_slots = 0;
  MailBoxTable[id].slot_size = -1;
	MailBoxTable[id].slots_used = 0;
	MailBoxTable[id].block_receive_queue = NULL;
	MailBoxTable[id].block_send_queue = NULL;
	MailBoxTable[id].slot_queue = NULL;
  //add any other attributes we may add later

} /* init_mailbox */



/* ------------------------------------------------------------------------
   Name - init_slot
   Purpose - Sets default values for slot in SlotTable
   Parameters - index for the SlotTable array
   Returns - Nothing
   Side Effects - Erases any previously set attributes if called again
   ----------------------------------------------------------------------- */
void init_slot(int index)
{
  SlotTable[index].slot_id = -1;
  SlotTable[index].status = EMPTY;
  SlotTable[index].next_slot_ptr = NULL;
  //add any other attributes we may add later

} /* init_slot */


void init_process(int pid)
{
	MboxProcTable[pid % MAXPROC].pid = -1;
	MboxProcTable[pid % MAXPROC].status = EMPTY;
	MboxProcTable[pid % MAXPROC].message = NULL;
	MboxProcTable[pid % MAXPROC].msg_size = -1;
	MboxProcTable[pid % MAXPROC].mbox_released = 0;
	MboxProcTable[pid % MAXPROC].next_block_send = NULL;
	MboxProcTable[pid % MAXPROC].next_block_receive = NULL;
}
/* ------------------------------------------------------------------------
   Name - add_process
   Purpose - Provides way to store message in process
   Parameters - pid, msg_ptr, msg_size
   Returns - Nothing
   Side Effects - Overwrites previously set attributes if called into same index
   ----------------------------------------------------------------------- */
void add_process(int pid, void *msg_ptr, int msg_size)
{
	MboxProcTable[pid%MAXPROC].pid = pid;
	MboxProcTable[pid%MAXPROC].status = ACTIVE;
	MboxProcTable[pid%MAXPROC].message = msg_ptr;
	MboxProcTable[pid%MAXPROC].msg_size = msg_size;
} /* add_process*/



/* ------------------------------------------------------------------------
   Name - set_slot
   Purpose - Sets attributes of specific slot in our slot table
   Parameters - index for the SlotTable array
   Returns - Slot pointer pointing to slot we were editing
   Side Effects - Erases any previously set attributes if called again
   ----------------------------------------------------------------------- */
slot_ptr set_slot(int index, int mbox_id, void * msg, int msg_size)
{
	SlotTable[index].mbox_id = mbox_id;
	SlotTable[index].status = USED;
	memcpy(SlotTable[index].message, msg, msg_size);
	SlotTable[index].message_size = msg_size;
	return &SlotTable[index];
} /* set_slot */


/* ------------------------------------------------------------------------
   Name - insert_slot
   Purpose - Insert slot pointer into slot queue inside mailbox object
   Parameters - the slot pointer and the mailbox we are going to insert into
   Returns - number of slots currently used
   Side Effects - ???
   ----------------------------------------------------------------------- */
int insert_slot(slot_ptr add_this, mbox_ptr some_mailbox)
{
	if (DEBUG2 && debugflag2) {
		console("insert_slot(): started... ");
	}

	slot_ptr head = some_mailbox->slot_queue;
	if (head == NULL)
	{
		some_mailbox->slot_queue = add_this;
	}
	else
	{
		while (head->next_slot_ptr != NULL)
		{
			head = head->next_slot_ptr;
		}
		head->next_slot_ptr = add_this;

	}

	if (DEBUG2 && debugflag2) {
		console(" and ended.\n");
	}

	return ++some_mailbox->slots_used;

} /* insert_slot */


/* ------------------------------------------------------------------------
   Name - find_empty_slot
   Purpose - Finds empty slot in slot table
   Parameters - None
   Returns - index to empty slot in slot table or -2 if nothing is found
   Side Effects - ???
   ----------------------------------------------------------------------- */
int find_empty_slot()
{
	for (int i=0; i < MAXSLOTS; i++)
	{
		if (SlotTable[i].status == EMPTY) return i;
	}
	return -2;
} /* find_empty_slot */



/* ------------------------------------------------------------------------
   Name - start1
   Purpose - Initializes mailboxes and interrupt vector.
             Start the phase2 test process.
   Parameters - one, default arg passed by fork1, not used here.
   Returns - one to indicate normal quit.
   Side Effects - lots since it initializes the phase2 data structures.
   ----------------------------------------------------------------------- */
int start1(char *arg)
{
	if (DEBUG2 && debugflag2)
		console("start1(): at beginning\n");

	check_kernel_mode("start1");

	int kid_pid, status;

	/* Disable interrupts */
	disableInterrupts();

	/* Initialize the mail box table, slots, & other data structures. */
	int i;
	for (i=0; i < MAXMBOX; i++)
	{
		init_mailbox(i);
	}

	/* Need to create zero-slot IO mboxes for clock, terminals and disks
	 * 1 for clock, 4 for terminal, 2 for disk devices
	 */
	for (i=0; i < 7; i++)
	{
			MboxCreate(0, 0);
	}

	/* Initializing all the slots */
	for (i=0; i < MAXSLOTS; i++)
	{
		init_slot(i);
	}

	/* Initializing processes inside proc table */
	for (i=0; i < MAXPROC; i++) {
		init_process(i);
	}

	/* Initialize int_vec and sys_vec, allocate mailboxes for interrupt
	*  handlers.  Etc... */
	int_vec[CLOCK_DEV] =	clock_handler2;
	int_vec[DISK_DEV] =		disk_handler;
	int_vec[TERM_DEV] =		term_handler;
	int_vec[SYSCALL_INT] = syscall_handler;

	for (int i = 0; i < MAXSYSCALLS; i++) sys_vec[i] = nullsys;

	enableInterrupts();

	/* Create a process for start2, then block on a join until start2 quits */
	if (DEBUG2 && debugflag2)
	console("start1(): fork'ing start2 process\n");
	kid_pid = fork1("start2", start2, NULL, 4 * USLOSS_MIN_STACK, 1);
	if ( join(&status) != kid_pid ) {
	console("start2(): join returned something other than start2's pid\n");
	}

	return 0;
} /* start1 */




/* ------------------------------------------------------------------------
Name
	MboxCreate
Purpose
	Gets a free mailbox from the table of mailboxes and initializes it
Parameters
	Maximum number of slots in the mailbox and the max size of a msg
	sent to the mailbox.
Returns
	-1 to indicate that no mailbox was created
	>=0 as the mailbox id
Side Effects - initializes one element of the mail box array.

-------------------

	(a) Allocate and initialize a location in your mailbox array. MAXMBOX from phase2.h is the size of this array.
	(b) Do not allocate slots. They are allocated only as needed to hold messages.

----------------------------------------------------------------------- */
int MboxCreate(int slots, int slot_size)
{
	if (DEBUG2 && debugflag2) console("MboxCreate(): started.\n");
	check_kernel_mode("MboxCreate");
	disableInterrupts();

	// First check if args are valid
	if (slots < 0 || slot_size > MAX_MESSAGE || slot_size < 0)
	{
		if (DEBUG2 && debugflag2)
			console("MboxCreate(): illegal value(s) for parameters.\n");
		enableInterrupts();
		return -1;
	}

	// Check for empty slot and return mailbox id
	// Sender will be blocked until a receiver collects the message or,
	// the receiver will be blocked until the sender sends the message
	for (int i=0; i<MAXMBOX; i++)
	{
		if (MailBoxTable[i].status == EMPTY)
		{
			if (DEBUG2 && debugflag2) console("MboxCreate(): found empty slot: %i.\n", i);
			MailBoxTable[i].mbox_id = i;
			MailBoxTable[i].num_slots = slots;
			MailBoxTable[i].slot_size = slot_size;
			MailBoxTable[i].status = USED;
			enableInterrupts();
			return MailBoxTable[i].mbox_id;
		}
	}
	//Otherwise if there are no slots then return -1
	if (DEBUG2 && debugflag2) console("MboxCreate(): no empty slots.\n");
	enableInterrupts();
	return -1;
} /* MboxCreate */


/* ------------------------------------------------------------------------
	Name
		MboxSend
	Purpose
		Put a message into a slot for the indicated mailbox.
		Block the sending process if no slot available.
	Parameters
		mailbox id, pointer to data of msg, # of bytes in msg.
	Returns
		-1 if invalid args
		0 if successful
	Side Effects
		None Known

-------------------



----------------------------------------------------------------------- */
int MboxSend(int mbox_id, void *msg_ptr, int msg_size)
{
	if (DEBUG2 && debugflag2) console("MboxSend(): started.\n");
	check_kernel_mode("MboxSend");
	disableInterrupts();

	/* First, check if args valid - THIS CAN BE A FUNCTION */
	if (MailBoxTable[mbox_id].status == EMPTY)
	{
		enableInterrupts();
		return -1;
	}

	//make sure that the ID is valid
	if (mbox_id > MAXMBOX || mbox_id < 0)
	{
		enableInterrupts();
		return -1;
	}

	//check msg_size and compare with slot_size that was set
	mbox_ptr this_mbox = &MailBoxTable[mbox_id];

	if (this_mbox->num_slots != 0 && msg_size > this_mbox->slot_size)
	{
		enableInterrupts();
		return -1;
	}

	//add process to MboxProcTable
	if (DEBUG2 && debugflag2) {
		console("MboxSend(): associating process with msg_ptr.\n");
	}
	int pid = getpid();

	add_process(pid, msg_ptr, msg_size);

	/* If there are no other blocked receive processes in our queue and no empty slots
	 * available, then add to send queue and block. check to make sure process
	 * hasn't been released.
	 */
	if (this_mbox->num_slots <= this_mbox->slots_used && this_mbox->block_receive_queue == NULL)
	{
		if (DEBUG2 && debugflag2) {
			console("MboxSend(): slots full and no processes in our block receive queue. ");
			console("Adding to send queue and blocking.\n");
		}

		if (this_mbox->block_send_queue == NULL)
		{
			this_mbox->block_send_queue = &MboxProcTable[pid%MAXPROC];
		}
		else
		{
			mbox_proc_ptr temp = this_mbox->block_send_queue;
			while (temp->next_block_send != NULL)
			{
				temp = temp->next_block_send;
			}
			temp->next_block_send = &MboxProcTable[pid%MAXPROC];
		}

		block_me(SEND_BLOCKED);
		if (MboxProcTable[pid%MAXPROC].mbox_released)
		{
			enableInterrupts();
			return -3;
		}

		if (is_zapped()) return -3;
		else return 0;
	}

	/* Otherwise if there are currently processes inside our receive queue
	 * then copy contents of the blocked receive message and unblock it.
	 */
	if (this_mbox->block_receive_queue != NULL)
	{
		if (DEBUG2 && debugflag2) {
			console("MboxSend(): receive processes found in block receive queue. Unblocking.\n");
		}

		int blocked_queue_pid = this_mbox->block_receive_queue->pid;

		if (msg_size > this_mbox->block_receive_queue->msg_size)
		{
			if (DEBUG2 && debugflag2) {
				console("MboxSend(): msg_size is greater than our block_receive_queue msg_size.\n");
			}
			this_mbox->block_receive_queue->status = FAILED;
			this_mbox->block_receive_queue = this_mbox->block_receive_queue->next_block_receive;
			unblock_proc(blocked_queue_pid);
			enableInterrupts();
			return 0;
		}

		//use memcpy here as document tells us to do
		memcpy(this_mbox->block_receive_queue->message, msg_ptr, msg_size);
		this_mbox->block_receive_queue->msg_size = msg_size;
		this_mbox->block_receive_queue = this_mbox->block_receive_queue->next_block_receive;
		unblock_proc(blocked_queue_pid);
		enableInterrupts();

		if (is_zapped()) return -3;
		else return 0;
	}

	/* This means that there are still some slots available and our block
	 * receive queue is empty. Grab the empty slot and initialize it for use
	 */
	int slot = find_empty_slot();
	if (slot == -2)
	{
		if (DEBUG2 && debugflag2) console("MboxSend(): could not locate empty slot.\n");
		halt(1);
	}

	//initialize the empty slot
	if (DEBUG2 && debugflag2) console("MboxSend(): filling empty slot.\n");

	slot_ptr new_slot = set_slot(slot, this_mbox->mbox_id, msg_ptr, msg_size);
	insert_slot(new_slot, this_mbox);

	enableInterrupts();
	if (is_zapped()) return -3;
	else return 0;
} /* MboxSend */


/* ------------------------------------------------------------------------
	Name
		MboxCondSend
	Purpose
		Conditionally send a message to a mailbox.
		Do not block the invoking process.
	Parameters
		mailbox id, pointer to data of msg, # of bytes in msg.
	Returns
		-3: process is zap’d.
		-2: mailbox full, message not sent; or no mbox slots available in the system.
		-1: illegal values given as arguments.
		0: message sent successfully.

	Side Effects
		none determined at this point

	Notes from lecture
		Does not block because we do not want to block the interrupt handler.

	Mail slot table overflow does not halt USLOSS. Return -2 in this case.

----------------------------------------------------------------------- */
int MboxCondSend(int mbox_id, void *msg_ptr, int msg_size)
{
	if (DEBUG2 && debugflag2) console("MboxCondSend(): started.\n");
	check_kernel_mode("MboxCondSend");
	disableInterrupts();

	if (mbox_id > MAXMBOX || mbox_id < 0)
	{
		enableInterrupts();
		return -1;
	}

	mbox_ptr this_mbox = &MailBoxTable[mbox_id];
	if (this_mbox->num_slots != 0 && msg_size > this_mbox->slot_size)
	{
		enableInterrupts();
		return -1;
	}

	//add process to MboxProcTable
	int pid = getpid();
	add_process(pid, msg_ptr, msg_size);

	//if there are no more empty slots then just return
	if (this_mbox->num_slots != 0 && this_mbox->num_slots == this_mbox->slots_used) {
		return -2;
	}

	//there are no slots and nothing currently blocked in our receive queue
	if (this_mbox->block_receive_queue == NULL && this_mbox->num_slots == 0)
	{
		return -1;
	}

	//check if our process is in the receive queue
	if (this_mbox->block_receive_queue != NULL)
	{
		if (msg_size > this_mbox->block_receive_queue->msg_size)
		{
			enableInterrupts();
			return -1;
		}
		memcpy(this_mbox->block_receive_queue->message, msg_ptr, msg_size);
		this_mbox->block_receive_queue->msg_size = msg_size;
		int blocked_queue_pid = this_mbox->block_receive_queue->pid;
		this_mbox->block_receive_queue = this_mbox->block_receive_queue->next_block_receive;
		unblock_proc(blocked_queue_pid);
		enableInterrupts();
		if (is_zapped()) return -3;
		else return 0;
	}

	//get empty slot
	int slot = find_empty_slot();
	if (slot == -2)
	{
		if (DEBUG2 && debugflag2) console("MboxSend(): could not locate empty slot.\n");
		return -2;
	}
	//insert slot
	slot_ptr new_slot = set_slot(slot, this_mbox->mbox_id, msg_ptr, msg_size);
	insert_slot(new_slot, this_mbox);

	enableInterrupts();
	if (is_zapped()) return -3;
	else return 0;
} /* MboxCondSend */



/* ------------------------------------------------------------------------
	Name
		MboxReceive
	Purpose
		Releases a previously created mailbox.
		Any process waiting on the mailbox should be zap’d
	Parameters
		mailbox id
	Returns
		-3: process was zap’d while releasing the mailbox.
		-1: the mailboxID is not a mailbox that is in use.
		0: successful
	Side Effects
		None known
   ----------------------------------------------------------------------- */
int MboxReceive(int mbox_id, void *msg_ptr, int msg_size)
{
	if (DEBUG2 && debugflag2) console("MboxReceive(): started.\n");
	check_kernel_mode("MboxReceive");
	disableInterrupts();

	if (MailBoxTable[mbox_id].status == EMPTY)
	{
		enableInterrupts();
		return -1;
	}

	if (msg_size < 0)
	{
		enableInterrupts();
		return -1;
	}

	//add process to MboxProcTable
	int pid = getpid();
	add_process(pid, msg_ptr, msg_size);

	mbox_ptr this_mbox = &MailBoxTable[mbox_id];
	if (this_mbox->num_slots == 0 && this_mbox->block_send_queue != NULL)
	{
		mbox_proc_ptr sender = this_mbox->block_send_queue;
		memcpy(msg_ptr, sender->message, sender->msg_size);
		this_mbox->block_send_queue = this_mbox->block_send_queue->next_block_send;
		unblock_proc(sender->pid);
		return sender->msg_size;
	}

	slot_ptr first_slot = this_mbox->slot_queue;

	//block when there are no messages available..
	if (first_slot == NULL)
	{
		if (this_mbox->block_receive_queue == NULL)
		{
			this_mbox->block_receive_queue = &MboxProcTable[pid % MAXPROC];
		}
		else
		{
			mbox_proc_ptr walker = this_mbox->block_receive_queue;
			while (walker->next_block_receive != NULL)
			{
				walker = walker->next_block_receive;
			}
			walker->next_block_receive = &MboxProcTable[pid % MAXPROC];
		}

		block_me(RECEIVE_BLOCKED);

		if (MboxProcTable[pid % MAXPROC].mbox_released)
		{
			enableInterrupts();
			return -3;
		}
		if (is_zapped())
		{
			enableInterrupts();
			return -3;
		}
		if (MboxProcTable[pid % MAXPROC].status == FAILED)
		{
			enableInterrupts();
			return -1;
		}

		enableInterrupts();
		return MboxProcTable[pid % MAXPROC].msg_size;

	}

	//this means that there are messages still available on slot list
	else
	{
		if (first_slot->message_size > msg_size)
		{
			enableInterrupts();
			return -1;
		}
		memcpy(msg_ptr, first_slot->message, first_slot->message_size);
		this_mbox->slot_queue = first_slot->next_slot_ptr;
		int size = first_slot->message_size;
		init_slot(first_slot->slot_id);
		this_mbox->slots_used--;

		if (this_mbox->block_send_queue != NULL)
		{
			int slot_index = find_empty_slot();
			slot_ptr new_slot = set_slot(slot_index, this_mbox->mbox_id,
				this_mbox->block_send_queue->message,
				this_mbox->block_send_queue->msg_size);

			insert_slot(new_slot, this_mbox);

			//wake up process blocked on send queue
			int pid = this_mbox->block_send_queue->pid;
			this_mbox->block_send_queue = this_mbox->block_send_queue->next_block_send;
			unblock_proc(pid);
		}
		enableInterrupts();
		if (is_zapped()) return -3;
		else return size;
	}

} /* MboxReceive */


/* ------------------------------------------------------------------------
	Name
		MboxCondReceive
	Purpose
		Conditionally receive a message from a mailbox. Do not block the invoking process.
	Parameters
		mailbox id, pointer to data of msg, # of bytes in msg.
	Returns
		-3: process is zap’d.
		-2: mailbox full, message not sent; or no mailbox slots available in the system.
		-1: illegal values given as arguments.
		0: message sent successfully.
	Side Effects
		None known
   ----------------------------------------------------------------------- */
int MboxCondReceive(int mbox_id, void *msg_ptr, int msg_size)
{
	if (DEBUG2 && debugflag2) console("MboxCondReceive(): started.\n");
	check_kernel_mode("MboxCondReceive");
	disableInterrupts();

	//check parameters
	if (MailBoxTable[mbox_id].status == EMPTY)
	{
		enableInterrupts();
		return -1;
	}

	mbox_ptr this_mbox = &MailBoxTable[mbox_id];

	if (msg_size < 0)
	{
		enableInterrupts();
		return -1;
	}

	//add process to MboxProcTable
	int pid = getpid();
	add_process(pid, msg_ptr, msg_size);

	//no slots but there is a process on send list
	if (this_mbox->num_slots == 0 && this_mbox->block_send_queue != NULL)
	{
		mbox_proc_ptr sender = this_mbox->block_send_queue;
		memcpy(msg_ptr, sender->message, sender->msg_size);
		this_mbox->block_send_queue = this_mbox->block_send_queue->next_block_send;
		unblock_proc(sender->pid);
		return sender->msg_size;
	}

	slot_ptr first_slot = this_mbox->slot_queue;

	//empty slot
	if (first_slot == NULL)
	{
		enableInterrupts();
		return -2;
	}
	//this means that there is a msg in the slot
	else
	{
		if (first_slot->message_size > msg_size)
		{
			enableInterrupts();
			return -1;
		}
		memcpy(msg_ptr, first_slot->message, first_slot->message_size);
		this_mbox->slot_queue = first_slot->next_slot_ptr;
		int size = first_slot->message_size;
		init_slot(first_slot->slot_id);
		this_mbox->slots_used--;

	// if there is a msg on the send list waiting for slot
	if (this_mbox->block_send_queue != NULL)
	{
		int slot_index = find_empty_slot();
		slot_ptr new_slot = set_slot(slot_index, this_mbox->mbox_id,
			this_mbox->block_send_queue->message,
			this_mbox->block_send_queue->msg_size);

		insert_slot(new_slot, this_mbox);

		//wake up process blocked on send queue
		int pid = this_mbox->block_send_queue->pid;
		this_mbox->block_send_queue = this_mbox->block_send_queue->next_block_send;
		unblock_proc(pid);
	}

	enableInterrupts();
	if (is_zapped()) return -3;
	else return size;

	}
} /* MboxReceive */



/* ------------------------------------------------------------------------
	Name
		MboxRelease
	Purpose
		Releases a previously created mailbox. Any process waiting on the mailbox should be zap’d.
	Parameters
		mailbox id
	Returns
		-3: process was zap’d while releasing the mailbox.
		1: the mailboxID is not a mailbox that is in use.
		0: successful completion.
	Side Effects

   ----------------------------------------------------------------------- */
int MboxRelease(int mbox_id)
{
	if (DEBUG2 && debugflag2) console("MboxRelease(): started.\n");
	check_kernel_mode("MboxRelease");
	disableInterrupts();

	//check parameters
	if (mbox_id < 0 || mbox_id >= MAXMBOX)
	{
		enableInterrupts();
		return -1;
	}
	if (MailBoxTable[mbox_id].status == EMPTY)
	{
		enableInterrupts();
		return -1;
	}

	mbox_ptr this_mbox = &MailBoxTable[mbox_id];

	//check to see if there are processes on blocked send and receive queues
	if (this_mbox->block_send_queue == NULL && this_mbox->block_receive_queue == NULL)
	{
		init_mailbox(mbox_id);
		enableInterrupts();
		if (is_zapped()) return -3;
		else return 0;
	}

	//otherwise let's clear house!
	else
	{
		this_mbox->status = EMPTY;
		//go through the send queue
		while (this_mbox->block_send_queue != NULL)
		{
			this_mbox->block_send_queue->mbox_released = 1;
			int pid = this_mbox->block_send_queue->pid;
			this_mbox->block_send_queue = this_mbox->block_send_queue->next_block_send;
			unblock_proc(pid);
			disableInterrupts();
		}
		//go through the receive queue
		while (this_mbox->block_receive_queue != NULL)
		{
			this_mbox->block_receive_queue->mbox_released = 1;
			int pid = this_mbox->block_receive_queue->pid;
			this_mbox->block_receive_queue = this_mbox->block_receive_queue->next_block_receive;
			unblock_proc(pid);
			disableInterrupts();
		}
	}

	init_mailbox(mbox_id);
	enableInterrupts();

	if(is_zapped()) return -3;
	else return 0;
} /* MboxReceive */


/* ------------------------------------------------------------------------
	Name
		WaitDevice
	Purpose
		Do a receive operation on the mbox associated with the unit of the type
	Parameters

	Returns
		-1: the proc was zapped while waiting
		0: successful completion.
	Side Effects

   ----------------------------------------------------------------------- */
int waitdevice(int type, int unit, int *status)
{
	if (DEBUG2 && debugflag2) console("waitdevice(): started.\n");
	check_kernel_mode("waitdevice");
	disableInterrupts();

	int check_receive;
	int device_id;
	int clock_id = 0;
	int disk_id[] = {1, 2};
	int term_id[] = {3, 4, 5, 6};

	switch(type)
	{
		case CLOCK_DEV:
			device_id = clock_id;
			break;

		case DISK_DEV:
			//to prevent it from picking non-existent values
			if (unit > 1 || unit < 0)
			{
				if (DEBUG2 && debugflag2) console("waitdevice(): invalid unit.\n");
				halt(1);
			}
			device_id = disk_id[unit];
			break;

		case TERM_DEV:
			//to prevent it from picking non-existent values
			if (unit > 3 || unit < 0)
			{
				if (DEBUG2 && debugflag2) console("waitdevice(): invalid unit.\n");
				halt(1);
			}
			device_id = term_id[unit];
			break;

		default:
			if (DEBUG2 && debugflag2) console("waitdevice(): invalid device.\n");
			halt(1);
	}

	check_receive = MboxReceive(device_id, status, sizeof(int));

	if (check_receive == -3) return -1;
	else return 0;
} /* WaitDevice */
