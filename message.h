#define DEBUG2 1

#define EMPTY    0
#define READY    1
#define FULL     2
#define RELEASE  3

typedef struct mail_slot *slot_ptr;
typedef struct mailbox mail_box;
typedef struct mbox_proc *mbox_proc_ptr;

struct mailbox {
   int           mbox_id;
   int           status;
   int           num_slots; //max number of slots
   int           slot_size; //max size of message in slot
   slot_ptr      slot_queue;
   /* other items as needed... */
};

struct mail_slot {
  int       slot_id;
  char      message[MAX_MESSAGE];
  int       message_size;
  slot_ptr  next_slot_ptr;
  int       mbox_id;
  int       status;
   /* other items as needed... */
};

struct psr_bits {
    unsigned int cur_mode:1;
    unsigned int cur_int_enable:1;
    unsigned int prev_mode:1;
    unsigned int prev_int_enable:1;
    unsigned int unused:28;
};

union psr_values {
   struct psr_bits bits;
   unsigned int integer_part;
};
