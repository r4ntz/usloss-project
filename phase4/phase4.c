
/* ------------------------------------------------------------------------
   phase3.c

   University of Arizona South
   Computer Science 452


   Rantz Marion & Mark Whitson

   ------------------------------------------------------------------------ */

/* ------------------------- Includes ----------------------------------- */
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <usloss.h>
#include <phase1.h>
#include <phase2.h>
#include <phase3.h>
#include <phase4.h>
#include <usyscall.h>
#include <provided_prototypes.h>
#include "driver.h"

/* -------------------------- Globals ------------------------------------- */
int debugflag4 = 1;

static int running; /*semaphore to synchronize drivers and start3*/

int terminate_clock;
int terminate_disk;

proc_struct Proc_Table[MAXPROC];
int disksems[DISK_UNITS];
int diskpids[DISK_UNITS];
int num_tracks[DISK_UNITS];
driver_proc_ptr diskQ[DISK_UNITS];

int char_receive[TERM_UNITS];
int char_send[TERM_UNITS];
int line_receive[TERM_UNITS];
int line_send[TERM_UNITS];
int user_write_boxes[TERM_UNITS];


proc_ptr sleepQ;


/* ------------------------- Prototypes ----------------------------------- */
void check_kernel_mode(char *);
void set_user_mode(void);
void disableInterrupts();
void enableInterrupts();
int start3(char *);
void sleep(sysargs *);
int sleep_real(int);
void disk_read(sysargs *);
int diskread_real(int, int, int, int, void *);
void disk_write(sysargs *);
int diskwrite_real(int, int, int, int, void *);
void disk_size(sysargs *);
int disksize_real(int, int *, int *, int *);
void insert_process();
void remove_process();
int diskread_handler(int);
int diskwrite_handler(int);
int dev_output(device_request *, int);
void insert_diskreq(driver_proc_ptr);
static int  ClockDriver(char *);
static int  DiskDriver(char *);

extern int start4(char *);
/* -------------------------- Functions ----------------------------------- */

void check_kernel_mode(char * function_name)
{
        if ((PSR_CURRENT_MODE & psr_get()) == 0)
        {
                console("Kernel Error: %s() not in kernel mode.\n", function_name);
                halt(1);
        }
}

void set_user_mode()
{
        psr_set(psr_get() & ~PSR_CURRENT_MODE);
}

void disableInterrupts()
{
        psr_set(psr_get() | PSR_CURRENT_INT);
}

void enableInterrupts()
{
        psr_set(psr_get() & ~PSR_CURRENT_INT);
}

void add_process()
{
        if (getpid() != Proc_Table[getpid() % MAXPROC].pid)
        {
                Proc_Table[getpid() % MAXPROC].pid = getpid();
                Proc_Table[getpid() % MAXPROC].status = ACTIVE;
                Proc_Table[getpid() % MAXPROC].mbox_id = MboxCreate(0,0);
                Proc_Table[getpid() % MAXPROC].sleep_ptr = NULL;
        }

        return;

}

void remove_process()
{
        MboxRelease(Proc_Table[getpid() % MAXPROC].mbox_id);
        Proc_Table[getpid() % MAXPROC].pid = -1;
        Proc_Table[getpid() % MAXPROC].status = EMPTY;
        Proc_Table[getpid() % MAXPROC].mbox_id = -1;
        Proc_Table[getpid() % MAXPROC].sleep_ptr = NULL;

        return;
}

int sleep_real(int seconds)
{
        if (DEBUG4 && debugflag4)
        {
                console("sleep_real(): started. seconds: %d\n", seconds);
        }

        if (seconds < 0) return -1;

        add_process();
        proc_ptr new_proc = &Proc_Table[getpid() % MAXPROC];

        int wake_time = sys_clock() + (1000000 * seconds);
        new_proc->wake_time = wake_time;

        if (sleepQ == NULL)
        {
                sleepQ = new_proc;
        }
        else
        {
                proc_ptr prev = sleepQ;
                if (new_proc->wake_time >= sleepQ->wake_time)
                {
                        proc_ptr walker = sleepQ->sleep_ptr;

                        while (walker != NULL && new_proc->wake_time > walker->wake_time)
                        {
                                prev = prev->sleep_ptr;
                                walker = walker->sleep_ptr;
                        }
                        prev->sleep_ptr = new_proc;
                        new_proc->sleep_ptr = walker;
                }
                else
                {
                        new_proc->sleep_ptr = prev;
                        sleepQ = new_proc;
                }
        }

        //block on private mbox
        MboxReceive(Proc_Table[getpid() % MAXPROC].mbox_id, NULL, 0);

        //remove from proc table
        remove_process();

        return 0;
}

void sleep(sysargs * arg)
{
        if (DEBUG4 && debugflag4)
        {
                console("sleep(): started\n");
        }

        int seconds = (int) arg->arg1;
        if (sleep_real(seconds) < 0)
        {
                arg->arg4 = (void *) -1;
        }
        else
        {
                arg->arg4 = (void *) 0;
        }
}

void add_driver_process(driver_proc_ptr some_proc)
{
        if (DEBUG4 && debugflag4)
        {
                console("add_driver_process(%d): started\n", some_proc->unit);
        }

        int unit = some_proc->unit;

        if (diskQ[unit] == NULL)
        {
                if (DEBUG4 && debugflag4)
                {
                        console("add_driver_process(%d): inserting at head of diskQ (only member)\n",
                                some_proc->unit);
                }
                diskQ[unit] = some_proc;
        }
        else
        {
                if (DEBUG4 && debugflag4)
                {
                        console("add_driver_process(%d): locating suitable slot inside diskQ\n",
                                some_proc->unit);
                }
                driver_proc_ptr prev = diskQ[unit];
                driver_proc_ptr walker = diskQ[unit]->next_ptr;
                if (some_proc->track_start > diskQ[unit]->track_start)
                {
                        while (walker != NULL && walker->track_start < some_proc->track_start &&
                               walker->track_start > prev->track_start)
                        {
                                prev = prev->next_ptr;
                                walker = walker->next_ptr;
                        }
                        prev->next_ptr = some_proc;
                        some_proc->next_ptr = walker;
                }
                else
                {
                        while (walker != NULL && prev->track_start <= walker->track_start)
                        {
                                prev = prev->next_ptr;
                                walker = walker->next_ptr;
                        }
                        while (walker != NULL && walker->track_start <= some_proc->track_start)
                        {
                                prev = prev->next_ptr;
                                walker = walker->next_ptr;
                        }
                }
        }
}



int disksize_real(int unit, int * sector_size, int * sectors_in_track, int * tracks_in_disk)
{
        if (DEBUG4 && debugflag4)
        {
                console("disksize_real(%d): started\n", unit);
        }

        int status;
        int result;

        if (unit < 0 || unit > 1)
        {
                return -1;
        }

        add_process();

        device_request req;
        req.opr = DISK_TRACKS;
        req.reg1 = (void *) tracks_in_disk;

        device_output(DISK_DEV, unit, &req);
        result = waitdevice(DISK_DEV, unit, &status);

        if (status == DEV_ERROR)
        {
                return -1;
        }
        if (result != 0)
        {
                return -1;
        }

        *sector_size = DISK_SECTOR_SIZE;
        *sectors_in_track = DISK_TRACK_SIZE;

        remove_process();

        return 0;
}

void disk_size(sysargs * arg)
{
        if (DEBUG4 && debugflag4)
        {
                console("disk_size(): started\n");
        }

        int result;

        int sector_size;
        int sectors_in_track;
        int tracks_in_disk;

        int unit = (int) arg->arg1;

        result = disksize_real(unit, &sector_size, &sectors_in_track, &tracks_in_disk);

        if (result == -1)
        {
                arg->arg4 = (void *) -1;
        }
        else
        {
                arg->arg4 = (void *) 0;
        }

        arg->arg1 = (void *) sector_size;
        arg->arg2 = (void *) sectors_in_track;
        arg->arg3 = (void *) tracks_in_disk;
}

int diskwrite_real(int unit, int track_start, int sector_start, int sectors, void * buffer)
{
        if (DEBUG4 && debugflag4)
        {
                console("diskwrite_real(%d): started. pid: %d, track_start: %d\n",
                        unit, getpid(), track_start);
        }

        driver_proc new_proc;

        if (unit < 0 || unit > 1)
        {
                if (DEBUG4 && debugflag4)
                        console("diskwrite_real(%d): unit incorrect value: %d\n",
                                unit, unit);
                return -1;
        }
        if (track_start < 0 || track_start > num_tracks[unit] - 1)
        {
                if (DEBUG4 && debugflag4)
                        console("diskwrite_real(%d): track_start incorrect value: %d\n",
                                unit, track_start);
                return -1;
        }
        if (sector_start < 0 || sector_start > DISK_TRACK_SIZE - 1)
        {
                if (DEBUG4 && debugflag4)
                        console("diskwrite_real(%d): sector_start incorrect value: %d\n",
                                unit, sector_start);
                return -1;
        }

        add_process();

        //build struct
        new_proc.unit = unit;
        new_proc.track_start = track_start;
        new_proc.sector_start = sector_start;
        new_proc.num_sectors = sectors;
        new_proc.disk_buf = buffer;
        new_proc.mbox_id = Proc_Table[getpid() % MAXPROC].mbox_id;
        new_proc.operation = DISK_WRITE;
        new_proc.next_ptr = NULL;

        add_driver_process(&new_proc);

        semv_real(disksems[unit]);

        MboxReceive(Proc_Table[getpid() % MAXPROC].mbox_id, NULL, 0);

        remove_process();

        return new_proc.status;

}

void disk_write(sysargs * arg)
{
        if (DEBUG4 && debugflag4)
        {
                console("disk_write(): started\n");
        }

        int result;

        void * buffer = arg->arg1;
        int sectors = (int) arg->arg2;
        int track_start = (int) arg->arg3;
        int sector_start = (int) arg->arg4;
        int unit = (int) arg->arg5;

        result = diskwrite_real(unit, track_start, sector_start, sectors, buffer);

        if (result == -1)
        {
                arg->arg4 = (void *) -1;
        }
        else
        {
                arg->arg4 = (void *) 0;
        }

        arg->arg1 = (void *) result;

        return;
}

int diskread_real(int unit, int track_start, int sector_start, int sectors, void * buffer)
{
        if (DEBUG4 && debugflag4)
        {
                console("diskread_real(%d): started\n", unit);
        }

        driver_proc new_proc;
        if (unit < 0 || unit > 1)
        {
                return -1;
        }
        if (track_start < 0 || track_start > num_tracks[unit] - 1)
        {
                return -1;
        }
        if (sector_start < 0 || sector_start > DISK_TRACK_SIZE - 1)
        {
                return -1;
        }

        add_process();

        //build struct
        new_proc.unit = unit;
        new_proc.track_start = track_start;
        new_proc.sector_start = sector_start;
        new_proc.num_sectors = sectors;
        new_proc.disk_buf = buffer;
        new_proc.mbox_id = Proc_Table[getpid() % MAXPROC].mbox_id;
        new_proc.operation = DISK_READ;
        new_proc.next_ptr = NULL;

        //add to our queue
        add_driver_process(&new_proc);

        //wake up driver
        semv_real(disksems[unit]);

        MboxReceive(Proc_Table[getpid() % MAXPROC].mbox_id, NULL, 0);

        remove_process();

        return new_proc.status;

}

void disk_read(sysargs * arg)
{
        if (DEBUG4 && debugflag4)
        {
                console("disk_read(): started\n");
        }

        int result;

        void * buffer = arg->arg1;
        int sectors = (int) arg->arg2;
        int track_start = (int) arg->arg3;
        int sector_start = (int) arg->arg4;
        int unit = (int) arg->arg5;

        result = diskread_real(unit, track_start, sector_start, sectors, buffer);

        if (result == -1)
        {
                arg->arg4 = (void *) -1;
        }
        else arg->arg4 = (void *) 0;

        arg->arg1 = (void *) result;

        return;
}

int start3(char *arg)
{
        char name[128];
        char diskbuf[10];
        int i;
        int clockPID;

        int pid;
        int status;
        terminate_clock = 1;
        terminate_disk = 1;

        //Check kernel mode here.
        check_kernel_mode("start3");

        /* Assignment system call handlers */
        sys_vec[SYS_SLEEP]     = sleep;
        sys_vec[SYS_DISKREAD]  = disk_read;
        sys_vec[SYS_DISKWRITE] = disk_write;
        sys_vec[SYS_DISKSIZE] = disk_size;


        /* Initialize the phase 4 process table */
        for (int i = 0; i < MAXPROC; i++)
        {
                Proc_Table[i].status = EMPTY;
                Proc_Table[i].pid    = -1;
        }

        /* Initialize sleepQ */
        sleepQ = NULL;
        for (int i = 0; i < DISK_UNITS; i++)
        {
                diskQ[i] = NULL;
        }

        /*
         * Create clock device driver
         * I am assuming a semaphore here for coordination.  A mailbox can
         * be used instead -- your choice.
         */
        running = semcreate_real(0);
        clockPID = fork1("Clock driver", ClockDriver, NULL, USLOSS_MIN_STACK, 2);
        if (clockPID < 0) {
                console("start3(): Can't create clock driver\n");
                halt(1);
        }

        //add to process table
        strcpy(Proc_Table[clockPID % MAXPROC].name, "Clock driver");
        Proc_Table[clockPID % MAXPROC].pid = clockPID;
        Proc_Table[clockPID % MAXPROC].status = ACTIVE;

        /*
         * Wait for the clock driver to start. The idea is that ClockDriver
         * will V the semaphore "running" once it is running.
         */

        semp_real(running);

        /*
         * Create the disk device drivers here.  You may need to increase
         * the stack size depending on the complexity of your
         * driver, and perhaps do something with the pid returned.
         */

        for (i = 0; i < DISK_UNITS; i++) {
                sprintf(diskbuf, "%d", i);
                sprintf(name, "DiskDriver%d", i);
                disksems[i] = semcreate_real(0);
                pid = fork1(name, DiskDriver, diskbuf, USLOSS_MIN_STACK, 2);
                if (pid < 0) {
                        console("start3(): Can't create disk driver %d\n", i);
                        halt(1);
                }

                diskpids[i] = pid;

                int sector, track;
                disksize_real(i, &sector, &track, &num_tracks[i]);

                strcpy(Proc_Table[pid & MAXPROC].name, name);
                Proc_Table[pid & MAXPROC].pid = pid;
                Proc_Table[pid & MAXPROC].status = ACTIVE;
        }


        /*
         * Create first user-level process and wait for it to finish.
         * These are lower-case because they are not system calls;
         * system calls cannot be invoked from kernel mode.
         * I'm assuming kernel-mode versions of the system calls
         * with lower-case names.
         */
        pid = spawn_real("start4", start4, NULL,  USLOSS_MIN_STACK, 3);
        console("0 - status: %d\n", status);
        pid = wait_real(&status);

        /*
         * Zap the device drivers
         */
        console("1\n");

        terminate_clock = 0;
        zap(clockPID); // clock driver
        join(&status);

        terminate_disk = 0;
        for (i = 0; i < DISK_UNITS; i++)
        {
                //unblock the device drivers

                semv_real(disksems[i]);
                zap(diskpids[i]);
                join(&status);

        }

        quit(0);
        return 0;
}

static int ClockDriver(char *arg)
{
        if (DEBUG4 && debugflag4)
        {
                console("ClockDriver(): started\n");
        }

        int result;
        int status;

        /*
         * Let the parent know we are running and enable interrupts.
         */
        semv_real(running);
        enableInterrupts();

        //infinite loop till zappd
        while(!is_zapped() && terminate_clock) {
                if (terminate_clock == 0) break;
                result = waitdevice(CLOCK_DEV, 0, &status);
                if (result != 0) {
                        return 0;
                }
                /*
                 * Compute the current time and wake up any processes
                 * whose time has come.
                 */
                while (sleepQ != NULL && sleepQ->wake_time < sys_clock())
                {
                        //get rid of other sleeping processes
                        int mbox_id = sleepQ->mbox_id;
                        sleepQ = sleepQ->sleep_ptr;
                        MboxSend(mbox_id, NULL, 0);
                }
        }

        return 0;
}

//helper function for device_output
int dev_output(device_request * req, int unit)
{
        if (DEBUG4 && debugflag4)
        {
                console("dev_output(%d): started\n", unit);
        }

        int status;
        int result;

        device_output(DISK_DEV, unit, req);

        result = waitdevice(DISK_DEV, unit, &status);

        if (status == DEV_ERROR)
        {
                diskQ[unit]->status = status;
                return -1;
        }
        if (result != 0) return -2;

        diskQ[unit]->status = status;

        return 0;
}

int diskwrite_handler(int unit)
{
        if (DEBUG4 && debugflag4)
        {
                console("diskwrite_handler(%d): started\n", unit);
        }

        int status = 0;
        int current_track = diskQ[unit]->track_start;
        int current_sector = diskQ[unit]->sector_start;

        device_request req;
        req.opr = DISK_SEEK;
        req.reg1 = (void *) current_track;

        //seek to initial track & write
        if (dev_output(&req, unit) < 0)
        {
                return -1;
        }

        for (int i = 0; i < diskQ[unit]->num_sectors; i++)
        {
                //if all sectors are used
                if (current_sector == DISK_TRACK_SIZE)
                {
                        current_sector = 0;
                        current_track++;

                        //if all tracks on disk are used
                        if (current_track == num_tracks[unit])
                        {
                                return -1;
                        }

                        req.opr = DISK_SEEK;
                        req.reg1 = (void *) current_track;

                        //seek to next track
                        if (dev_output(&req, unit) < 0)
                        {

                                console("diskwrite_handler: failed to write\n");
                                return -1;
                        }
                }

                req.opr = DISK_WRITE;
                req.reg1 = (void *) current_sector;
                req.reg2 = diskQ[unit]->disk_buf + (512 * i);

                //write sector to disk
                if (dev_output(&req, unit) < 0)
                {
                        diskQ[unit] = diskQ[unit]->next_ptr;
                        diskQ[unit]->status = status;
                        console("diskwrite_handler: failed to write\n");
                        return -1;
                }

                current_sector++;
        }

        //remove req and wake up calling process
        int mbox_id = diskQ[unit]->mbox_id;
        diskQ[unit] = diskQ[unit]->next_ptr;
        MboxSend(mbox_id, NULL, 0);

        return 0;
}

int diskread_handler(int unit)
{
        if (DEBUG4 && debugflag4)
        {
                console("diskread_handler(%d): started\n", unit);
        }

        char buf[512];
        int index = 0;
        int current_track = diskQ[unit]->track_start;
        int current_sector = diskQ[unit]->sector_start;

        device_request req;
        req.opr = DISK_SEEK;
        req.reg1 = (void *) current_track;

        //initial seek operation
        if (dev_output(&req, unit) < 0)
        {
                return -1;
        }

        //all the read operations. may need to change track
        for (int i = 0; i < diskQ[unit]->num_sectors; i++)
        {
                if (current_sector == DISK_TRACK_SIZE)
                {
                        current_sector = 0;
                        current_track++;

                        if (current_track == num_tracks[unit]) return -1;

                        req.opr = DISK_SEEK;
                        req.reg1 = (void *) current_track;

                        if (dev_output(&req, unit) < 0) return -1;

                }

                //make device_request for reading
                req.opr = DISK_READ;
                req.reg1 = (void *) current_sector;
                req.reg2 = buf;

                //do read
                if (dev_output(&req, unit) < 0)
                {
                        diskQ[unit] = diskQ[unit]->next_ptr;
                        return -1;
                }

                //copy what was read into buff
                memcpy( ((char *) diskQ[unit]->disk_buf + index), buf, 512);
                index += 512;
                current_sector++;
        }

        //wake up calling process and remove from queue
        MboxSend(diskQ[unit]->mbox_id, NULL, 0);
        diskQ[unit] = diskQ[unit]->next_ptr;

        return 0;
}

static int DiskDriver(char *arg)
{
        if (DEBUG4 && debugflag4)
        {
                console("DiskDriver(): started\n");
        }

        int unit = atoi(arg);
        int result = 0;

        while (!is_zapped() && terminate_disk)
        {
                if (terminate_disk == 0) break;

                if (diskQ[unit] != NULL)
                {
                        switch(diskQ[unit]->operation)
                        {
                        case DISK_READ:
                                result = diskread_handler(unit);
                                break;
                        case DISK_WRITE:
                                result = diskwrite_handler(unit);
                                break;
                        default:
                                console("DiskDriver(%d): Invalid disk request\n", unit);
                        }
                }
                else
                {
                        //otherwise block and wait for another disk request
                        if (DEBUG4 && debugflag4)
                        {
                                console("DiskDriver(%d): blocking and waiting..\n", unit);
                        }
                        semp_real(disksems[unit]);
                }

                if (result < 0)
                {
                        console("DiskDriver(%d): read/write fail\n", unit);
                }

        }

        return 0;
}
