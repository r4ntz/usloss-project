#define DEBUG4  1

//for process table
#define EMPTY   0
#define ACTIVE  1

typedef struct driver_proc * driver_proc_ptr;
typedef struct proc_struct * proc_ptr;

typedef struct proc_struct
{
        proc_ptr sleep_ptr; //sleep queue

        int wake_time;
        char name[MAXNAME];
        char start_arg[MAXARG];
        int pid;
        int (*func)(char *);
        int status;
        int mbox_id;
} proc_struct;

typedef struct driver_proc {
        driver_proc_ptr next_ptr;

        int wake_time; /* for sleep syscall */
        int been_zapped;

        /* Used for disk requests */
        int operation; /* DISK_READ, DISK_WRITE, DISK_SEEK, DISK_TRACKS */
        int track_start;
        int sector_start;
        int num_sectors;
        void *disk_buf;

        //more fields to add
        int mbox_id;
        int status;
        int unit;

} driver_proc;
