#define DEBUG 0

#define NOT_STARTED -1
#define QUIT 0
#define ZAPBLOCKED 1
#define READY 2
#define RUNNING 3
#define ZOMBIE 4
#define JOINBLOCKED 5

typedef struct proc_struct proc_struct;

typedef struct proc_struct * proc_ptr;

struct proc_struct {
   proc_ptr       next_proc_ptr;  /* use this for the ReadyList on each process */
   proc_ptr       next_zappd_ptr; /* use this for the zapped queue on each process */
   proc_ptr       child_proc_ptr;
   proc_ptr       next_sibling_ptr;
   char           name[MAXNAME];     /* process's name */
   char           start_arg[MAXARG]; /* args passed to process */
   context        state;             /* current context for process */
   short          pid;               /* process id */
   int            priority;
   int (* start_func) (char *);   /* function where process begins -- launch */
   char          *stack;
   unsigned int   stacksize;
   int            status;         /* READY, BLOCKED, QUIT, etc. */

   /* other fields as needed... */
   int            zapped; /* keeps track of number of zapped processes */
   int            start_time;
   int            cpu_time;
   int            time_sliced;
   int *          code;
   proc_ptr       parent_ptr;
   int            num_children;
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

/* Some useful constants.  Add more as needed... */
#define NO_CURRENT_PROCESS NULL
#define MINPRIORITY 5
#define MAXPRIORITY 1
#define SENTINELPID 1
#define SENTINELPRIORITY LOWEST_PRIORITY
#define MAXTIME 80 //milliseconds
