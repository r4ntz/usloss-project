#define DEBUG2 1

#define EMPTY 0
#define BLOCKED 1

typedef struct mail_slot *slot_ptr;
typedef struct mailbox mail_box;
typedef struct mbox_proc *mbox_proc_ptr;

struct mailbox {
   int           mbox_id;
   int           status;
   int           num_slots; //max number of slots
   int           slot_size; //max size of message in slot
   /* other items as needed... */
};

struct mail_slot {
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
