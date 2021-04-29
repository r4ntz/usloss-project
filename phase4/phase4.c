
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
int debugflag4 = 0;

static int running; /*semaphore to synchronize drivers and start3*/

proc_struct Proc_Table[MAXPROC];
int disksems[DISK_UNITS];

int char_receive[TERM_UNITS];
int char_send[TERM_UNITS];

int line_receive[TERM_UNITS];
int line_send[TERM_UNITS];

int user_write_boxes[TERM_UNITS];

int num_tracks[DISK_UNITS];

proc_ptr sleepQ;

driver_proc_ptr diskQ[DISK_UNITS];

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
void term_read(sysargs *);
int termread_real(int, int, char *);
void term_write(sysargs *);
int termwrite_real(int, int, char *);
void insert_process();
void remove_process();
int diskread_handler(int);
int diskwrite_handler(int);
int dev_output(device_request *, int);
void insert_diskreq(driver_proc_ptr);
static int  ClockDriver(char *);
static int  DiskDriver(char *);
static int TermDriver(char *);

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

int TermReader(char * arg)
{
        int unit = atoi(arg);
        char line[MAXLINE + 1];
        int index = 0;
        char buffer;

        while (1) {
                // get char from driver
                MboxReceive(char_receive[unit], &buffer, sizeof(char));

                if (is_zapped()) return 0;

                // apend char to line
                line[index] = buffer;
                index++;

                // send line to mailbox when line is complete
                if (buffer == '\n' || index >= MAXLINE) {
                        line[index] = 0;
                        MboxCondSend(line_receive[unit], (void *) line, MAXLINE + 1);
                        index = 0;
                }
        }
}

int TermWriter(char * arg)
{
        int unit = atoi(arg);
        int chars;
        char line[MAXLINE];
        int control = 0;

        /* Run while not zapped
           block on mBoxRecieve and wait for termWriteReal to send the line
           check to see if you are zapped, if so then return.
           Get line and set a control int to XMIT and do a device output to enable writing.
         */
        while (!is_zapped()) {
                chars = MboxReceive(line_send[unit], line, MAXLINE);
                if (chars > MAXLINE) {
                        chars = 80;
                }
                if (is_zapped()) {
                        return 0;
                }
                for (int i = 0; i < chars; i++) {
                        control = 0;
                        control = TERM_CTRL_CHAR(control, line[i]);
                        control = TERM_CTRL_XMIT_INT(control);
                        control = TERM_CTRL_RECV_INT(control);
                        control = TERM_CTRL_XMIT_CHAR(control);

                        device_output(TERM_DEV, unit,((void *)(long) control));

                        MboxReceive(char_send[unit], NULL, 0);
                }
                control = 2;
                device_output(TERM_DEV, unit, &control);
                //Send number of chars written to user
                MboxSend(user_write_boxes[unit], &chars, sizeof(int));
        }

        return 0;
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
                diskQ[unit] = some_proc;
        }
        else
        {
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
        }
}

int termwrite_real(int unit, int buf_size, char * buf)
{
        if (DEBUG4 && debugflag4)
        {
          console("termwrite_real(%d): started\n", unit);
        }

        int chars;
        if (unit < 0 || unit > 3)
        {
                return -1;
        }
        if (buf_size < 0)
        {
                return -1;
        }

        MboxSend(line_send[unit], buf, buf_size);

        MboxReceive(user_write_boxes[unit], &chars, sizeof(int));

        return chars;
}

void term_write(sysargs * arg)
{
        if (DEBUG4 && debugflag4)
        {
          console("term_write(): started\n");
        }

        int result;
        int unit = (int) arg->arg3;
        int buf_size = (int) arg->arg2;
        char * buf = (char *) arg->arg1;

        result = termwrite_real(unit, buf_size, buf);

        arg->arg2 = (void *) result;

        if (result == -1)
        {
                arg->arg4 = (void *) -1;
        }
        else
        {
                arg->arg4 = (void *) 0;
        }

        return;
}

int termread_real(int unit, int buf_size, char * buf)
{
        if (DEBUG4 && debugflag4)
        {
          console("termread_real(%d): started\n", unit);
        }

        if (unit < 0 || unit > 3)
        {
                return -1;
        }
        if (buf_size < 0)
        {
                return -1;
        }

        char buffer[MAXLINE + 1];
        MboxReceive(line_receive[unit], buf, MAXLINE + 1);
        int buf_length = strlen(buffer);
        buffer[buf_length] = '\n';

        if (buf_size < buf_length)
        {
                memcpy(buf, buffer, buf_size + 1);
                return buf_length;
        }
        else
        {
                memcpy(buf, buffer, buf_length);
                return buf_length;
        }

        return -1;
}

void term_read(sysargs * arg)
{
        if (DEBUG4 && debugflag4)
        {
          console("term_read(): started\n");
        }

        int result;
        int unit = (int) arg->arg3;
        int buf_size = (int) arg->arg2;
        char * buf = (char *) arg->arg1;

        result = termread_real(unit, buf_size, buf);

        arg->arg2 = (void *) result;

        if (result == -1)
        {
                arg->arg4 = (void *) -1;
        }
        else
        {
                arg->arg4 = (void *) 0;
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
          console("diskwrite_real(%d): started\n", unit);
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

static int TermDriver(char *arg)
{
        if (DEBUG4 && debugflag4)
        {
          console("TermDriver(): started\n");
        }

        int status;
        int result;
        int unit = atoi(arg);
        int control = 2;

        //turn on recv interrupts
        device_output(TERM_DEV, unit, &control);

        while (!is_zapped())
        {
                result = waitdevice(TERM_DEV, unit, &status);
                if (is_zapped()) return 0;
                if (result != 0) return 0;

                char c = TERM_STAT_CHAR(status);
                //if busy then give to term_read
                if (TERM_STAT_RECV(status) == DEV_BUSY)
                {
                        MboxCondSend(char_receive[unit], &c, sizeof(char));
                }
                //otherwise give to term_writer
                if (TERM_STAT_XMIT(status) == DEV_READY)
                {
                        MboxCondSend(char_send[unit], NULL, 0);
                }
        }

        return 0;
}

int start3(char *arg)
{
        char name[128];
        char buf[10];
        int i;
        int clockPID;
        int diskPID[DISK_UNITS];
        int termdriverPID[TERM_UNITS];
        int termreaderPID[TERM_UNITS];
        int termwriterPID[TERM_UNITS];
        int pid;
        int status;

        //Check kernel mode here.
        check_kernel_mode("start3");

        /* Assignment system call handlers */
        sys_vec[SYS_SLEEP]     = sleep;
        sys_vec[SYS_DISKREAD]  = disk_read;
        sys_vec[SYS_DISKWRITE] = disk_write;
        sys_vec[SYS_DISKSIZE] = disk_size;
        sys_vec[SYS_TERMREAD]  = term_read;
        sys_vec[SYS_TERMWRITE] = term_write;


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
                sprintf(buf, "%d", i);
                sprintf(name, "DiskDriver%d", i);
                disksems[i] = semcreate_real(0);
                pid = fork1(name, DiskDriver, buf, USLOSS_MIN_STACK, 2);
                if (pid < 0) {
                        console("start3(): Can't create disk driver %d\n", i);
                        halt(1);
                }

                diskPID[i] = pid;

                int sector, track;
                disksize_real(i, &sector, &track, &num_tracks[i]);

                strcpy(Proc_Table[pid & MAXPROC].name, name);
                Proc_Table[pid & MAXPROC].pid = pid;
                Proc_Table[pid & MAXPROC].status = ACTIVE;
        }

        //Create the terminal device drivers here
        for (i = 0; i < TERM_UNITS; i++)
        {
                sprintf(buf, "%d", i);
                sprintf(name, "TermDriver%d", i);

                pid = fork1(name, TermDriver, buf, USLOSS_MIN_STACK, 2);
                if (pid < 0)
                {
                        console("Can't create term driver. Halting..\n");
                        halt(1);
                }

                termdriverPID[i] = pid; //store this for zapping

                strcpy(Proc_Table[pid & MAXPROC].name, name);
                Proc_Table[pid & MAXPROC].pid = pid;
                Proc_Table[pid & MAXPROC].status = ACTIVE;

                //TermReader process
                sprintf(buf, "%d", i);
                sprintf(name, "TermReader%d", i);

                pid = fork1(name, TermReader, buf, USLOSS_MIN_STACK, 2);
                if (pid < 0)
                {
                        console("Can't create term reader. Halting..\n");
                        halt(1);
                }

                termreaderPID[i] = pid;

                strcpy(Proc_Table[pid & MAXPROC].name, name);
                Proc_Table[pid & MAXPROC].pid = pid;
                Proc_Table[pid & MAXPROC].status = ACTIVE;

                //TermWriter process
                sprintf(buf, "%d", i);
                sprintf(name, "TermWriter%d", i);

                pid = fork1(name, TermWriter, buf, USLOSS_MIN_STACK, 2);
                if (pid < 0)
                {
                        console("Can't create term writer. Halting..\n");
                        halt(1);
                }

                termwriterPID[i] = pid;

                strcpy(Proc_Table[pid & MAXPROC].name, name);
                Proc_Table[pid & MAXPROC].pid = pid;
                Proc_Table[pid & MAXPROC].status = ACTIVE;

                // ----

                char_receive[i] = MboxCreate(1, sizeof(char));
                char_send[i] = MboxCreate(0, 0);
                line_receive[i] = MboxCreate(10, MAXLINE + 1);
                line_send[i] = MboxCreate(0, MAXLINE);
                user_write_boxes[i] = MboxCreate(0, sizeof(int));
        }



        /*
         * Create first user-level process and wait for it to finish.
         * These are lower-case because they are not system calls;
         * system calls cannot be invoked from kernel mode.
         * I'm assuming kernel-mode versions of the system calls
         * with lower-case names.
         */
        pid = spawn_real("start4", start4, NULL,  8 * USLOSS_MIN_STACK, 3);
        pid = wait_real(&status);

        /*
         * Zap the device drivers
         */


        zap(clockPID); // clock driver

        for (i = 0; i < DISK_UNITS; i++)
        {
                //unblock the device drivers

                semv_real(disksems[i]);

                zap(diskPID[i]);

        }


        char termfile[20];
        FILE * kill;
        for (i = 0; i < TERM_UNITS; i++)
        {
                MboxCondSend(char_receive[i], NULL, 0);
                zap(termreaderPID[i]);

                MboxCondSend(line_send[i], "end", 3);
                zap(termwriterPID[i]);
        }

        for (i = 0; i < TERM_UNITS; i++)
        {
                sprintf(termfile, "./term%d.in", i);
                kill = fopen(termfile, "a");
                fprintf(kill, "Please stop driver.\n");
                fclose(kill);

                zap(termdriverPID[i]);
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
        while(!is_zapped()) {
                result = waitdevice(CLOCK_DEV, 0, &status);
                if (result != 0) {
                        return 0;
                }
                /*
                 * Compute the current time and wake up any processes
                 * whose time has come.
                 */
                 while (sleepQ != NULL && sleepQ->wake_time <= sys_clock())
                 {
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
        int result;

        while (!is_zapped())
        {
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
                        semp_real(disksems[unit]);
                }

                if (result < 0) console("DiskDriver(%d): read/write fail\n", unit);

        }

        return 0;
}
