/* ------------------------------------------------------------------------
   phase4.c

   University of Arizona South
   Computer Science 452


   Rantz Marion & Mark Whitson

   TO-DO: finish termread, termwrite, their real equivalents, debug,
   clean up any unused or ambigiuous variables, add new functions to prototypes

   ------------------------------------------------------------------------ */

/* ------------------------- Includes ----------------------------------- */
#include <stdlib.h>
#include <stdio.h>
#include <strings.h>
#include <string.h>
#include <usloss.h>
#include <phase1.h>
#include <phase2.h>
#include <phase3.h>
#include <phase4.h>
#include <usyscall.h>
#include <provided_prototypes.h>
#include "driver.h"


/* -------------------------- Globals ------------------------------------- */
static int running; /*semaphore to synchronize drivers and start3*/
static struct driver_proc Driver_Table[MAXPROC];
request_ptr topQ[DISK_UNITS];
request_ptr bottomQ[DISK_UNITS];
static int diskpids[DISK_UNITS];
static int disk_sem[DISK_UNITS];
static int disk_req[DISK_UNITS];
static int disk_arm[DISK_UNITS];
static int termpids[TERM_UNITS][3];
static int num_tracks[DISK_UNITS];
driver_proc_ptr sleepQ;
int debugflag4 = 1;

int terminate_disk;
int terminate_clock;
int terminate_term;

int char_receive[TERM_UNITS];
int char_send[TERM_UNITS];
int line_read[TERM_UNITS];
int line_write[TERM_UNITS];
int pid_box[TERM_UNITS];

/* ------------------------- Prototypes ----------------------------------- */
static int  ClockDriver(char *);
static int  DiskDriver(char *);
int start3(char *);
void check_kernel_mode(char *);
void sleep(sysargs *);
int sleep_real(int);
void diskread(sysargs *);
void diskwrite(sysargs *);
void disksize(sysargs *);
void termread(sysargs *);
void termwrite(sysargs *);

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

void enable_interrupts()
{
        psr_set(psr_get() & ~PSR_CURRENT_INT);
}

void disable_interrupts()
{
        psr_set(psr_get() | PSR_CURRENT_INT);
}

int sleep_real(int seconds)
{
        if (DEBUG4 && debugflag4)
        {
                console("sleep_real(): starting. seconds: %d\n", seconds);
        }

        //get and assign wake_time which is sys_clock + seconds
        int wake_time = sys_clock() + (seconds * 1000000);
        int pid = 0;
        getPID_real(&pid);
        Driver_Table[pid % MAXPROC].wake_time = wake_time;

        //insert at front of queue if higher wake_time or if NULL
        if (sleepQ == NULL || sleepQ->wake_time > wake_time)
        {
                if (sleepQ == NULL) sleepQ = &Driver_Table[pid % MAXPROC];
                else
                {
                        Driver_Table[pid % MAXPROC].next_sleep = sleepQ;
                        sleepQ = &Driver_Table[pid % MAXPROC];
                }
        }
        else
        {
                driver_proc_ptr walker = sleepQ;
                driver_proc_ptr prev = NULL;
                while (walker != NULL && walker->wake_time < wake_time)
                {
                        prev = walker;
                        walker = walker->next_sleep;
                }

                prev->next_sleep = &Driver_Table[pid % MAXPROC];
                Driver_Table[pid % MAXPROC].next_sleep = walker;
        }

        semp_real(Driver_Table[pid % MAXPROC].sleep_sem);

        return 0;

}

void sleep(sysargs * args)
{
        if (DEBUG4 && debugflag4) console("sleep(): starting\n");
        int seconds = (int) args->arg1;
        int status = sleep_real(seconds);

        if (status == 1) args->arg4 = (void *) -1;
        else args->arg4 = (void *) 0;

        return;
}

void diskreq(request_ptr req, int unit)
{
        //find place to insert Q
        request_ptr Q;
        if (req->track > disk_arm[unit])
        {
                Q = topQ[unit];
        }
        else
        {
                Q = bottomQ[unit];
        }

        request_ptr walker = Q;
        request_ptr prev = NULL;

        //in the case where Q is empty
        if (walker == NULL)
        {
                Q = req;
                return;
        }

        while (walker != NULL && walker->track < req->track)
        {
                prev = walker;
                walker = walker->next_req;
        }
        prev->next_req = req;
        req->next_req = walker;

        //wake up disk
        semv_real(disk_sem[unit]);
}

void disk_seek(int unit, int track)
{
        if (DEBUG4 && debugflag4) console("disk_seek(): starting\n");

        if (track >= num_tracks[unit])
        {
                halt(0);
                return;
        }

        device_request req;
        req.opr = DISK_SEEK;
        req.reg1 = (void *) track;

        device_output(DISK_DEV, unit, &req);
        int status;
        int res = waitdevice(DISK_DEV, unit, &status);
        if (DEBUG4 && debugflag4)
        {
                console("disk_seek(): waitdevice returned. status: %d\n", status);
        }

        if (res != 0)
        {
                if (DEBUG4 && debugflag4) console("disk_seek(): waitdevice returned non zero value..\n");
        }

        return;
}

int diskread_real(int unit, int track, int first, int sectors, void * buffer)
{
        if (DEBUG4 && debugflag4) console("diskread_real(): starting\n");

        request_ptr req;
        req->track = track;
        req->start_sector = first;
        req->num_sectors = sectors;
        req->waiting_pid = getpid();
        req->buffer = &buffer;
        req->req_type = DISK_READ;
        req->next_req = NULL;

        ///add request to queue
        if (DEBUG4 && debugflag4)
        {
                console("diskread_real: adding to queue\n");
        }

        diskreq(req, unit);

        //block calling process
        if (DEBUG4 && debugflag4)
        {
                console("diskread_real: blocking calling process\n");
        }

        semp_real(Driver_Table[getpid() % MAXPROC].disk_sem);

        return 0;
}

void diskread(sysargs * args)
{
        if (DEBUG4 && debugflag4) console("diskread(): starting\n");

        int sectors = (int) args->arg2;
        int track = (int) args->arg3;
        int first = (int) args->arg4;
        int unit = (int) args->arg5;
        void * buffer = args->arg1;

        //perform read
        int status = diskread_real(unit, track, first, sectors, buffer);

        //check for bad input
        if (status == -1)
        {
                args->arg4 = (void *) -1;
                return;
        }

        args->arg1 = (void *) status;
        args->arg4 = (void *) 0;

        return;
}

int diskwrite_real(int unit, int track, int first, int sectors, void * buffer)
{
        if (DEBUG4 && debugflag4) console("diskwrite_real(): starting\n");

        request_ptr req;
        req->track = track;
        req->start_sector = first;
        req->num_sectors = sectors;
        req->waiting_pid = getpid();
        req->buffer = &buffer;
        req->req_type = DISK_WRITE;
        req->next_req = NULL;

        //add request to Q
        if (DEBUG4 && debugflag4)
        {
                console("diskwrite_real: adding to queue\n");
        }
        diskreq(req, unit);

        //block calling process
        if (DEBUG4 && debugflag4)
        {
                console("diskwrite_real: blocking calling process\n");
        }
        semp_real(Driver_Table[getpid() % MAXPROC].disk_sem);

        return 0;
}

void diskwrite(sysargs * args)
{
        if (DEBUG4 && debugflag4) console("diskwrite(): starting\n");

        int sectors = (int) args->arg2;
        int track = (int) args->arg3;
        int first = (int) args->arg4;
        int unit = (int) args->arg5;
        void * buffer = args->arg1;

        //perform write
        int status = diskwrite_real(unit, track, first, sectors, buffer);

        //check for bad input
        if (status == -1)
        {
                args->arg4 = (void *) -1;
                return;
        }

        args->arg1 = (void *) status;
        args->arg4 = (void *) 0;

        return;
}

int disksize_real(int unit, int * sector, int * track, int * disk)
{
        if (DEBUG4 && debugflag4) console("disksize_real(): starting\n");

        if (unit < 0 || unit > DISK_UNITS) return -1;

        *sector = DISK_SECTOR_SIZE;
        *track = DISK_TRACK_SIZE;
        *disk = num_tracks[unit];

        if (DEBUG4 && debugflag4)
        {
                console("disksize_real:\tsector: %d, num sectors: %d, num_tracks: %d\n", sector, track, disk);
        }

        return 0;
}

void disksize(sysargs * args)
{
        if (DEBUG4 && debugflag4) console("disksize(): starting\n");

        int unit = (int) args->arg1;
        int sector;
        int track;
        int disk;

        //check for bad input
        int status = disksize_real(unit, &sector, &track, &disk);

        if (status == -1)
        {
                if (DEBUG4 && debugflag4)
                {
                        console("disksize: bad status\n");
                }
                args->arg4 = (void *) -1;
                return;
        }

        //everything looks good so set args
        if (DEBUG4 && debugflag4)
        {
                console("disksize:\tsector: %d, num sectors: %d, num_tracks: %d\n", sector, track, disk);
        }

        args->arg1 = (void *) sector;
        args->arg2 = (void *) track;
        args->arg3 = (void *) disk;
        args->arg4 = (void *) 0;

        return;
}

int termread_real(int unit, int size, char * buffer)
{
  if (DEBUG4 && debugflag4) console("termread_real(): starting\n");

  char line[MAXLINE];

  //check for line
  int result = MboxReceive(line_read[unit], line, size);

  memcpy(buffer, line, size);

  //check result
  if (result < 0) return -1;

  return result;

}
void termread(sysargs * args)
{
        if (DEBUG4 && debugflag4) console("termread(): starting\n");

        char * buffer = (char *) args->arg1;
        int size = (int) args->arg2;
        int unit = (int) args->arg3;

        int status = termread_real(unit, size, buffer);

        //check status
        if (status == -1)
        {
                args->arg4 = (void *) -1;
                return;
        }

        //set args
        args->arg2 = (void *) status;
        args->arg4 = (void *) 0;

        return;
}

int termwrite_real(int unit, int size, char * buffer)
{
    if (DEBUG4 && debugflag4) console("termwrite_real(): starting\n");

    //send pid
    char pid[10];
    sprintf(pid, "%d", getpid());
    MboxSend(pid_box[unit], pid, sizeof(int));

    //send text
    int result = MboxSend(line_write[unit], buffer, size);

    //check result
    if (result < 0) return -1;

    //block until done
    semp_real(Driver_Table[getpid() % MAXPROC].term_sem);

    return result;
}

void termwrite(sysargs * args)
{
        if (DEBUG4 && debugflag4) console("termwrite(): starting\n");

        char * buffer = (char *) args->arg1;
        int size = (int) args->arg2;
        int unit = (int) args->arg3;

        //check size
        int status = termwrite_real(unit, size, buffer);

        //check status
        if (status == -1)
        {
          args->arg4 = (void *) -1;
          return;
        }

        //set args
        args->arg2 = (void *) status;
        args->arg4 = (void *) 0;
        return;
}
static int ClockDriver(char *arg)
{
        if (DEBUG4 && debugflag4) console("ClockDriver(): starting\n");

        int result;
        int status;

        /*
         * Let the parent know we are running and enable interrupts.
         */
        semv_real(running);
        psr_set(psr_get() | PSR_CURRENT_INT);
        while(!is_zapped() && terminate_clock) {
                result = waitdevice(CLOCK_DEV, 0, &status);
                if (result != 0) return 0;
                /*
                 * Compute the current time and wake up any processes
                 * whose time has come.
                 */
                while (sleepQ != NULL && sleepQ->wake_time < sys_clock())
                {
                        //wake sleeper
                        semv_real(sleepQ->sleep_sem);

                        //remove head of sleepQ and set new head for while loop
                        driver_proc_ptr walker = sleepQ->next_sleep;
                        sleepQ->next_sleep = NULL;
                        sleepQ->wake_time = -1;
                        sleepQ = walker;
                }
        }

        return 0;
}

static int DiskDriver(char *arg)
{

        int unit = atoi(arg);
        device_request my_request;
        int result;
        int status;
        int * tracks;

        driver_proc_ptr current_req;

        if (DEBUG4 && debugflag4)
                console("DiskDriver(%d): started\n", unit);

        topQ[unit] = NULL;
        bottomQ[unit] = NULL;
        disk_sem[unit] = semcreate_real(0);
        disk_req[unit] = semcreate_real(0);
        disk_arm[unit] = 0;

        /* Get the number of tracks for this disk */
        my_request.opr  = DISK_TRACKS;
        my_request.reg1 = &tracks;

        result = device_output(DISK_DEV, unit, &my_request);

        if (result != DEV_OK) {
                console("DiskDriver %d: did not get DEV_OK on DISK_TRACKS call\n", unit);
                console("DiskDriver %d: is the file disk%d present???\n", unit, unit);
                halt(1);
        }

        waitdevice(DISK_DEV, unit, &status);

        if (DEBUG4 && debugflag4)
        {
                console("DiskDriver(%d): tracks = %d\n", unit, num_tracks[unit]);
        }

        num_tracks[unit] = *tracks;

        //let parent know and enable interrupts
        semv_real(running);
        enable_interrupts();

        while (!is_zapped() && terminate_disk)
        {
                semp_real(disk_sem[unit]);
                if (!terminate_disk)
                {
                        if (DEBUG4 && debugflag4) console("DiskDriver: #%d breaking loop\n", unit);
                        break;
                }
                request_ptr req = topQ[unit];
                topQ[unit] = topQ[unit]->next_req;

                disk_seek(unit, req->track);

                for (int i = 0; i < req->num_sectors; i++)
                {
                        device_request single_req;
                        single_req.opr = req->req_type;

                        //sector may change, based on i
                        single_req.reg1 = (void *) ((req->start_sector + i) % 16);

                        //sector may change depedent on sector we are visiting
                        single_req.reg2 = &(req->buffer) + (512 * i);

                }

                semv_real(Driver_Table[req->waiting_pid].disk_sem);
        }
        //more code
        return 0;
}

static int TermDriver(char * arg)
{
        int unit = atoi(arg);
        int status;

        if (DEBUG4 && debugflag4) console("TermDriver: #%d starting\n", unit);

        //let parent know
        semv_real(running);

        //turn on read in interrupts
        int control = 0;
        control = TERM_CTRL_RECV_INT(control);
        int res = device_output(TERM_DEV, unit, (void *) control);
        if (res != DEV_OK)
        {
                if (DEBUG4 && debugflag4)
                {
                        console("TermDriver: quit unexpectedly. res: %d\n", res);
                }

                halt(0);
        }

        //infite loop till zappd
        while (!is_zapped())
        {
                //wait for it to run
                int result = waitdevice(TERM_INT, 0, &status);
                if (result != 0)
                {
                        quit(0);
                }

                //check for receive char
                if (TERM_STAT_RECV(status) == DEV_BUSY)
                {
                        char c = TERM_STAT_CHAR(status);
                        //send msg saying char needs to be received
                        MboxSend(char_receive[unit], &c, sizeof(int));
                }

                //check for send char
                if (TERM_STAT_XMIT(status) == DEV_READY)
                {
                        char c = TERM_STAT_CHAR(status);
                        //send msg saying char needs to be sent
                        MboxSend(char_send[unit], &c, sizeof(int));
                }
        }

        return 0;
}

static int TermReader(char * arg)
{
        int unit = atoi(arg);
        int pos = 0;
        char line[MAXLINE];


        //let parent know
        semv_real(running);

        //infinite loop till zapped
        while(!is_zapped())
        {
                char receive[1]; //to hold received char

                //wait till there is something to read in
                MboxReceive(char_receive[unit], receive, sizeof(int));

                if (!terminate_term)
                {
                        if (DEBUG4 && debugflag4)
                        {
                                console("TermReader: terminate_term is %d, unit is %d\n", terminate_term, unit);
                        }
                        break;
                }

                //place character in line for sending later
                line[pos++] = (char) receive[0];

                //see if we can send line
                if ((char) receive[0] == '\n' || pos == MAXLINE)
                {
                        //send to the mailbox for reading
                        MboxCondSend(line_read[unit], line, sizeof(line));

                        for (int i = 0; i < MAXLINE; i++)
                        {
                                line[i] = '\0';
                        }

                        //then reset position
                        pos = 0;
                }

        }

        return 0;
}

static int TermWriter(char * arg)
{
        int unit = atoi(arg);

        //let parent know
        semv_real(running);

        //infinite loop till zapped
        while (!is_zapped())
        {
                char receive[MAXLINE];

                int count = 0;
                count = TERM_CTRL_XMIT_INT(count);
                count = TERM_CTRL_RECV_INT(count);
                device_output(TERM_DEV, unit, (void *) count);

                //wait until termwriter_reak sends line
                MboxReceive(line_write[unit], receive, MAXLINE);

                if (terminate_term)
                {
                        if (DEBUG4 && debugflag4)
                        {
                                console("TermWriter: terminate_term is %d, unit is %d\n", terminate_term, unit);
                        }

                        break;
                }

                //iterate through the line
                for (int i = 0; i < strlen(receive); i++)
                {
                        char * c;
                        //get char from term driver
                        MboxReceive(char_receive[unit], c, sizeof(int));

                        //transmit it
                        int control = 0;
                        control = TERM_CTRL_CHAR(control, c[0]);
                        control = TERM_CTRL_XMIT_INT(control);
                        control = TERM_CTRL_XMIT_CHAR(control);

                        //check if reutnred properly
                        int res = device_output(TERM_DEV, unit, (void *) control);

                        if (res != DEV_OK)
                        {
                                if (DEBUG4 && debugflag4)
                                {
                                        console("TermWriter: quit unexpectedly. res: %d\n", res);
                                }

                                halt(0);
                        }
                }

                //wait till termwriter_real send its pid
                char pid_c[10];
                MboxReceive(pid_box[unit], pid_c, sizeof(int));
                int pid = atoi((char *) pid_c);

                //wake up waiting process
                semv_real(Driver_Table[pid % MAXPROC].term_sem);
        }

        return 0;
}

int start3(char *arg)
{
        if (DEBUG4 && debugflag4) console("start3(): starting\n");


        char name[128];
        char termbuf[10];
        int i;
        int clockPID;
        int pid;
        int status;
        terminate_disk = 1;
        terminate_clock = 1;
        terminate_term = 1;

        /*
         * Check kernel mode here.
         */
        check_kernel_mode("start3");

        /* Assignment system call handlers */
        sys_vec[SYS_SLEEP]     = sleep;
        sys_vec[SYS_DISKREAD]  = diskread;
        sys_vec[SYS_DISKWRITE] = diskwrite;
        sys_vec[SYS_DISKSIZE]  = disksize;
        sys_vec[SYS_TERMREAD]  = termread;
        sys_vec[SYS_TERMWRITE] = termwrite;


        /* Initialize the phase 4 process table */
        for (int i = 0; i < MAXPROC; i++)
        {
                Driver_Table[i].wake_time = -1;
                Driver_Table[i].sleep_sem = semcreate_real(0);
                Driver_Table[i].term_sem = semcreate_real(0);
                Driver_Table[i].disk_sem = semcreate_real(0);
                Driver_Table[i].next_sleep = NULL;
        }

        for (int i = 0; i < TERM_UNITS; i++)
        {
                char_receive[i] = MboxCreate(1, 1);
                char_send[i] = MboxCreate(1, 1);
                line_read[i] = MboxCreate(10, MAXLINE);
                line_write[i] = MboxCreate(10, MAXLINE);
                pid_box[i] = MboxCreate(10, MAXLINE);
        }

        /*
         * Create clock device driver
         * I am assuming a semaphore here for coordination.  A mailbox can
         * be used instead -- your choice.
         */
        running = semcreate_real(0);
        clockPID = fork1("Clock driver", ClockDriver, NULL, USLOSS_MIN_STACK, 2);

        if (clockPID < 0)
        {
                console("start3(): Can't create clock driver\n");
                halt(1);
        }

        strcpy(Driver_Table[clockPID % MAXPROC].name, "Clock driver");
        Driver_Table[clockPID % MAXPROC].pid = clockPID;
        Driver_Table[clockPID % MAXPROC].status = ACTIVE;

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

        if (DEBUG4 && debugflag4) console("start3(): creating disk drivers\n");

        for (int i = 0; i < DISK_UNITS; i++)
        {
                sprintf(termbuf, "%d", i);
                sprintf(name, "DiskDriver%d", i);
                diskpids[i] = fork1(name, DiskDriver, termbuf, USLOSS_MIN_STACK, 2);
                if (diskpids[i] < 0)
                {
                        console("start3(): Can't create disk driver %d\n", i);
                        halt(1);
                }
        }

        //Create the terminal device drivers here.
        for (int i = 0; i < TERM_UNITS; i++)
        {
                sprintf(termbuf, "%d", i);

                //term driver
                termpids[i][0] = fork1(name, TermDriver, termbuf, USLOSS_MIN_STACK, 2);
                if (termpids[i][0] < 0)
                {
                        console("start3(): Can't create term driver %d\n", i);
                        halt(1);
                }

                //term reader
                termpids[i][1] = fork1(name, TermReader, termbuf, USLOSS_MIN_STACK, 2);
                if (termpids[i][0] < 0)
                {
                        console("start3(): Can't create term driver %d\n", i);
                        halt(1);
                }

                //term writer
                termpids[i][2] = fork1(name, TermWriter, termbuf, USLOSS_MIN_STACK, 2);
                if (termpids[i][1] < 0)
                {
                        console("start3(): Can't create term reader %d\n", i);
                        halt(1);
                }

                //wait for all to start
                semp_real(running);
                semp_real(running);
                semp_real(running);
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

        //zap clock
        zap(clockPID); // clock driver
        join(&status); /* for the Clock Driver */
        if (DEBUG4 && debugflag4) console("start3(): clock closed\n");

        //zap disk
        for (int i = 0; i < DISK_UNITS; i++)
        {
                semv_real(disk_sem[i]);
                zap(diskpids[i]);
                join(&status);
                if (DEBUG4 && debugflag4) console("start3(): disk #%d closed\n", i);
        }

        //zap term readers
        terminate_term = 0;
        for (int i = 0; i < TERM_UNITS; i++)
        {
                MboxSend(char_receive[i], (char *) 'c', sizeof(int));
                join(&status);
                if (DEBUG4 && debugflag4) console("start3(): term reader #%d\n", i);
        }

        //zap term writers
        for (int i = 0; TERM_UNITS; i++)
        {
                MboxSend(line_write[i], (char *) 'c', sizeof(int));
                join(&status);
                if (DEBUG4 && debugflag4) console("start3(): term writer #%d\n", i);
        }

        //zap term drivers
        for (int i = 0; i < TERM_UNITS; i++)
        {
                zap(termpids[i][0]);
                join(&status);
                if (DEBUG4 && debugflag4) console("start3(): term driver #%d\n", i);
        }

        return 0;
}
