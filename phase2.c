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

/* the mail boxes */
mail_box MailBoxTable[MAXMBOX];
mail_slot SlotTable[MAXSLOTS];


/* -------------------------- Functions ----------------------------------- */

/* ------------------------------------------------------------------------
   Name - clock_handler2
   Purpose - I'm guessing same as clock_handler from phase1. Don't know yet
   Parameters - Same as clock_handler from phase1
   Returns - Nothing
   Side Effects - None
   ----------------------------------------------------------------------- */
void clock_handler2(int dev, void * unit)
{
	if (DEBUG2 && debugflag2) console("clock_handler2(): started.\n");
	time_slice();

} /* clock_handler2 */



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
	for (i=0; i < MAXSLOTS; i++)
	{
		init_slot(i);
	}
	/* Initialize int_vec and sys_vec, allocate mailboxes for interrupt
	*  handlers.  Etc... */
	int_vec[CLOCK_DEV] = clock_handler2;

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
	if (DEBUG2 && debugflag2) console("MboxCreate(): called.\n");
	check_kernel_mode();
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
	// First, check if args valid - THIS CAN BE A FUNCTION
	// Also need to validate that mbox_id is not only a possible vlaue
	// but also an active mailbox
	if mbox_id > || < || OR "" *msg_ptr OR "" msg_size
		return -1;

/*	SECOND STEP
	If slot is available in this mailbox, allocate a slot
	from your mail slot table. MAXSLOTS determines the size
	of the mail slot array. MAX MESSAGE determines the max
	number of bytes that can be held in the slot.
	-If mail slot overflows, shoult halt USLOSS_MIN_STACK
*/

	// End this function by blocking if no msg slot available
	while no msg available
		block_me();

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
	if (DEBUG2 && debugflag2) console("MboxCondSend(): Conditionally sending.\n");
	// First, check if args valid - THIS CAN BE A FUNCTION - MboxCheck?
	if mbox_id > || < || OR "" *msg_ptr OR "" msg_size
		return -1;
	// Second, validate mbox full/no slots available
	else if (slots < 0 || slot_size > MAXSLOTS)
		return -2;
	// Third, send message
	else
		send message?
		return 0;
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










