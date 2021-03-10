/* ------------------------------------------------------------------------
	phase2.c

	University of Arizona South
	Computer Science 452


	Rantz Marion & Mark Whitson




--------------------------------
Notes and Ideas

	Blocking & Unblocking
		IF proc A is blocked from sending because mbox is full
		THEN receive operation should unblock A

		IF proc B receives empty msg from mbox and is blocked
		THEN unblocking B should be fone by send operation to mbox


	Do we need to place send/receive operations in a while loop to determine they are following FIFO?

	Testing for kernel mode must be done on 100% of functions.

	Items to add to the mailbox struct in message.h?
		Calling process PID
		Calling process PRI
		Queue int to count, validate FIFO

	Phase 1 functions available
		fork1, join, quit, zap, is zapped, getpid, dump processes, block me, unblock proc, read cur start time, and time slice

------------------------------------------------------------------------ */


/* ------------------------- Includes ----------------------------------- */

#include <phase1.h>
#include <phase2.h>
#include <usloss.h>
#include "message.h"


/* ------------------------- Prototypes ----------------------------------- */

//Phase 2 Prototypes

int start1 (char *);
int MboxCreate(int slots, int slot_size);
int MboxSend(int mbox_id, void *msg_ptr, int msg_size);
int MboxCondSend(int mbox_id, void *msg_ptr, int msg_size);
int MboxReceive(int mbox_id, void *msg_ptr, int msg_size);
int MboxCondReceive(int mbox_id, void *msg_ptr, int msg_size);
int MboxRelease(int mbox_id);
int MboxCheck (int mbox_id, void *msg_ptr, int msg_size);
void clock_handler2(int, void *);
void disk_handler(int, long);
void term_handler(int, long);
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
extern void check_kernel_mode(char *);
extern void enableInterrupts(void);
extern void disableInterrupts(void);

/* -------------------------- Globals ------------------------------------- */

int debugflag2 = 1;
int clock_intervals = 0;

/* the mail boxes */
mail_box MailBoxTable[MAXMBOX];
mail_slot SlotTable[MAXSLOTS];

/* proc table */
mbox_proc MboxProcTable[MAXPROC];

/* system call vector */
void (*sys_vec[MAXSYSCALLS])(sysargs * args);

/* -------------------------- Functions ----------------------------------- */

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
void disk_handler(int dev, long unit)
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
	int mbox_id = unit + 1;
	int ret = device_input(dev, unit, &status);
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
void term_handler(int dev, long unit)
{
	if (DEBUG2 && debugflag2) console("term_handler(): started.\n");
	check_kernel_mode("term_handler");
	disableInterrupts();

	if (dev != TERM_DEV)
	{
		if (DEBUG && debugflag2)
		{
			console("term_handler(): wrong device\n");
		}
		halt(1);
	}

	int status;
	int mbox_id = unit + 3;
	int ret = device_input(dev, unit, &status);
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
  MailBoxTable[id].num_slots = -1;
  MailBoxTable[id].slot_size = -1;
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
  MailBoxTable[index].status = EMPTY;
  MailBoxTable[index].next_slot_ptr = NULL;
  //add any other attributes we may add later

} /* init_slot */



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
	memcpy(SlotTable[index].message, msg_ptr, msg_size);
	SlotTable[index].msg_size = msg_size;
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
			return ++some_mailbox->slots_used;

} /* insert_slot */


/* ------------------------------------------------------------------------
   Name - find_empty_slot
   Purpose - Finds empty slot in slot table
   Parameters - None
   Returns - index to empty slot in slot table
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

	/* Initialize int_vec and sys_vec, allocate mailboxes for interrupt
	*  handlers.  Etc... */
	int_vec[CLOCK_DEV] = clock_handler2;
	int_vec[DISK_DEV] = disk_handler;
	int_vec[TERM_DEV] = term_handler;

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
	if (slots < 0 || slot_size > MAXSLOTS)
	{
		if (DEBUG2 && debugflag2)
			console("MboxCreate(): slot_size larger than MAXSLOTS and/or slots (no. of slots) is smaller than 0.\n");
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
			MailBoxTable[i].status = BLOCKED;
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
	mbox_proc_ptr mbox_ptr = &MailBoxTable[mbox_id];
	if (mbox_ptr->num_slots != 0 && msg_size > mbox_ptr->slot_size)
	{
		enableInterrupts();
		return -1;
	}

	int pid = getpid();
	MboxProcTable[pid%MAXPROC].pid = pid;
	MboxProcTable[pid%MAXPROC].status = ACTIVE;
	MboxProcTable[pid%MAXPROC].message = msg_ptr;
	MboxProcTable[pid%MAXPROC].msg_size = msg_size;

	/* If there are no other blocked receive processes in our queue and no empty slots
	 * available, then add to send queue and block. check to make sure process
	 * hasn't been released.
	 */
	if (mbox_ptr->num_slots <= mbox_ptr->slots_used && mbox_ptr->block_receive_queue == NULL)
	{
		if (mbox_ptr->block_send_queue == NULL)
		{
			mbox_ptr->block_send_queue = &MboxProcTable[pid%MAXPROC];
		}
		else
		{
			mbox_proc_ptr temp = mbox_ptr->block_send_queue;
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
	if (mbox_ptr->block_receive_queue != NULL)
	{
		int blocked_queue_pid = mbox_ptr->block_receive_queue->pid;

		if (msg_size > mbox_ptr->block_receive_queue->msg_size)
		{
			mbox_ptr->block_receive_queue->status = FAILED;
			mbox_ptr->block_receive_queue = mbox_ptr->block_receive_queue->next_block_receive;
			unblock_proc(blocked_queue_pid);

			enableInterrupts();
			return -1;
		}

		//use memcpy here as document tells us to do
		memcpy(mbox_ptr->block_receive_queue->message, msg_ptr, msg_size);
		mbox_ptr->block_receive_queue = mbox_ptr->block_receive_queue->next_block_receive;
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
	slot_ptr new_slot = set_slot(slot, mbox_ptr->mbox_id, msg_ptr, msg_size);
	insert_slot(new_slot, mbox_ptr);

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

	mbox_proc_ptr mbox_ptr = &MailBoxTable[mbox_id];
	if (mbox_ptr->num_slots != 0 && msg_size > mbox_ptr->slot_size)
	{
		enableInterrupts();
		return -1;
	}

	int pid = getpid();
	MboxProcTable[pid%MAXPROC].pid = pid;
	MboxProcTable[pid%MAXPROC].status = ACTIVE;
	MboxProcTable[pid%MAXPROC].message = msg_ptr;
	MboxProcTable[pid%MAXPROC].msg_size = msg_size;

	//if there are no more empty slots then just return
	if (mbox_ptr->num_slots != 0 && mbox_ptr->num_slots == mbox_ptr->slots_used) {
		return -2;
	}

	//there are no slots and nothing currently blocked in our receive queue
	if (mbox_ptr->block_receive_queue == NULL && mbox_ptr->num_slots == 0)
	{
		return -1;
	}

	//check if our process is in the receive queue
	if (mbox_ptr->block_receive_queue != NULL)
	{
		if (msg_size > mbox_ptr->block_receive_queue->msg_size)
		{
			enableInterrupts();
			return -1;
		}
		memcpy(mbox_ptr->block_receive_queue->message, msg_ptr, msg_size);
		mbox_ptr->block_receive_queue->msg_size = msg_size;
		int blocked_queue_pid = mbox_ptr->block_receive_queue->pid;
		mbox_ptr->block_receive_queue = mbox_ptr->block_receive_queue->next_block_receive;
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
	slot_ptr new_slot = set_slot(slot, mbox_ptr->mbox_id, msg_ptr, msg_size);
	insert_slot(new_slot, mbox_ptr);

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

	// End this function by blocking if no msg waiting
	while no msg waiting
		block_me();

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

} /* WaitDevice */





// Validates int mbox_id, *msg_ptr, msg_size valid args
int MboxCheck (int mbox_id, void *msg_ptr, int msg_size)
{
	// First, check for a vlaid mbox ID
	if mbox is invalid?
		if (DEBUG2 && debugflag2)
			console("Mailbox Error: Invalid Mbox ID of %d\n", mbox_id);
		return -1
	// Second, check for a valid *msg_ptr
	if
		if (DEBUG2 && debugflag2)
			console("Mailbox Error: Invalid Mbox ptr of %d\n", *msg_ptr);
		return -1
	// Third, check for a valid msg_size
	if (msg_size <0 || msg_size >MAX_MESSAGE) // can be zero-max len
		if (DEBUG2 && debugflag2)
			console("Mailbox Error: Invalid Mbox size of %d\n", msg_size);

		return -1


	// Determined to be valid by negation
	return 0
}
