#define DEBUG4 1

#define ACTIVE 1

typedef struct driver_proc * driver_proc_ptr;

struct driver_proc
{
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
        char name[MAXNAME];
        int pid;
        int status;

};
