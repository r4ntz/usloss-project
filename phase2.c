/* ------------------------------------------------------------------------
	phase2.c

	University of Arizona South
	Computer Science 452


	Rantz Marion & Mark Whitson




--------------------------------
Notes and Ideas

	Items to add to the mailbox struct in message.h?
		Calling process PID
		Calling process PRI
		Queue int to count, validate FIFO

	Phase 1 functions available
		fork1, join, quit, zap, is zapped, getpid, dump processes, block me, unblock proc, read cur start time, and time slice


Notes from a post:

typedef enum
{
   INIT = 0, //initialized
   AVAILABLE, //created, available for use
   FULL, //for blocking?
   RELEASE //MboxRelease requirement
} mailbox_status;

typedef struct mail_slot *slot_ptr;
typedef struct mailbox mail_box;
typedef struct mbox_proc *mbox_proc_ptr;

struct mailbox
{
   int      mbox_id;
   /* other items as needed...
   int      slots; // number of slots of mailbox
   int      slots_full;    // number of slots being used
   slot_ptr slot_que;   // linked list containing location of slots for mailbox
   mailbox_status      status;  // status of mailbox?
   int      slot_size;  // size of slot in mailbox
};

struct mail_slot {
   int      mbox_id; //id of mailbox where slot lives
   int      status;  //full, empty, avail
   // other items as needed...
   int      slot_id; //id associated with slot (0,1,2...)
   char     message[MAX_MESSAGE]; //message stored in slot
   int      message_size; //size of slot
   slot_ptr next_slot; //next slot in mailbox of id mbox_id


------------------------------------------------------------------------ */


/* ------------------------- Includes ----------------------------------- */

#include <phase1.h>
#include <phase2.h>
#include <usloss.h>
#include "message.h"


/* ------------------------- Prototypes ----------------------------------- */

//Phase 2 Prototypes

int start1 (char *);
extern int start2 (char *);



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


/* -------------------------- Functions ----------------------------------- */

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

   /* Initialize the mail box table, slots, & other data structures.
    * Initialize int_vec and sys_vec, allocate mailboxes for interrupt
    * handlers.  Etc... */

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
   Name - MboxCreate
   Purpose - gets a free mailbox from the table of mailboxes and initializes it
   Parameters - maximum number of slots in the mailbox and the max size of a msg
                sent to the mailbox.
   Returns - -1 to indicate that no mailbox was created, or a value >= 0 as the
             mailbox id.
   Side Effects - initializes one element of the mail box array.
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
    if (MailBoxTable[i].status == EMPTY) {
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
   Name - MboxSend
   Purpose - Put a message into a slot for the indicated mailbox.
             Block the sending process if no slot available.
   Parameters - mailbox id, pointer to data of msg, # of bytes in msg.
   Returns - zero if successful, -1 if invalid args.
   Side Effects - none.
   ----------------------------------------------------------------------- */
int MboxSend(int mbox_id, void *msg_ptr, int msg_size)
{
	// First, check if args valid - THIS CAN BE A FUNCTION
	if mbox_id > || < || OR "" *msg_ptr OR "" msg_size
		return -1



	// End this function by blocking if no msg slot available
	while no msg available
		block_me()

} /* MboxSend */


/* ------------------------------------------------------------------------
   Name - MboxCondSend
   Purpose - Conditionally send a message to a mailbox.
		Do not block the invoking process.
   Parameters - mailbox id, pointer to data of msg, # of bytes in msg.
   Returns -
		-3: process is zap’d.
		-2: mailbox full, message not sent; or no mailbox slots available in the system.
		-1: illegal values given as arguments.
		0: message sent successfully.

   Side Effects -
   ----------------------------------------------------------------------- */
int MboxCondSend(int mbox_id, void *msg_ptr, int msg_size)
{

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
		none?
   ----------------------------------------------------------------------- */
int MboxReceive(int mbox_id, void *msg_ptr, int msg_size)
{

	// End this function by blocking if no msg waiting
	while no msg waiting
		block_me()

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
	Side Effects -
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
