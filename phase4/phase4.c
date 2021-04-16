/* ------------------------------------------------------------------------
   phase4.c

   University of Arizona South
   Computer Science 452


   Rantz Marion & Mark Whitson

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
static int diskpids[DISK_UNITS];
static int num_tracks[DISK_UNITS];
int debugflag4 = 1;

/* ------------------------- Prototypes ----------------------------------- */
static int  ClockDriver(char *);
static int  DiskDriver(char *);
int start3(char *);
void sleep(sysargs *);
void diskread(sysargs *);
void diskwrite(sysargs *);
void disksize(sysargs *);

extern int start4(char *);


/* -------------------------- Functions ----------------------------------- */

void sleep(sysargs * args)
{
        if (DEBUG4 && debugflag4) console("sleep(): starting\n");
        return;
}

void diskread(sysargs * args)
{
        if (DEBUG4 && debugflag4) console("diskread(): starting\n");
        return;
}

void diskwrite(sysargs * args)
{
        if (DEBUG4 && debugflag4) console("diskwrite(): starting\n");
        return;
}

void disksize(sysargs * args)
{
        if (DEBUG4 && debugflag4) console("disksize(): starting\n");
        return;
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

        /*
         * Check kernel mode here.
         */


        /* Assignment system call handlers */
        sys_vec[SYS_SLEEP]     = sleep;
        sys_vec[SYS_DISKREAD]  = diskread;
        sys_vec[SYS_DISKWRITE] = diskwrite;
        sys_vec[SYS_DISKSIZE]  = disksize;

        //more for this phase's system call handlings


        /* Initialize the phase 4 process table */


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

        for (i = 0; i < DISK_UNITS; i++)
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

        semp_real(running);
        semp_real(running);


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
        join(&status); /* for the Clock Driver */

        return 0;
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
        while(!is_zapped()) {
                result = waitdevice(CLOCK_DEV, 0, &status);
                if (result != 0) {
                        return 0;
                }
                /*
                 * Compute the current time and wake up any processes
                 * whose time has come.
                 */
        }

        return 0;
}

static int DiskDriver(char *arg)
{

        int unit = atoi(arg);
        device_request my_request;
        int result;
        int status;

        driver_proc_ptr current_req;

        if (DEBUG4 && debugflag4)
                console("DiskDriver(%d): started\n", unit);


        /* Get the number of tracks for this disk */
        my_request.opr  = DISK_TRACKS;
        my_request.reg1 = &num_tracks[unit];

        result = device_output(DISK_DEV, unit, &my_request);

        if (result != DEV_OK) {
                console("DiskDriver %d: did not get DEV_OK on DISK_TRACKS call\n", unit);
                console("DiskDriver %d: is the file disk%d present???\n", unit, unit);
                halt(1);
        }

        waitdevice(DISK_DEV, unit, &status);
        if (DEBUG4 && debugflag4)
                console("DiskDriver(%d): tracks = %d\n", unit, num_tracks[unit]);


        //more code
        return 0;
}
