/*
 *  File:  libuser.c
 *
 *  Description:  This file contains the interface declarations
 *                to the OS kernel support package.
 *
 */

#include <phase1.h>
#include <phase2.h>
#include <libuser.h>
#include <usyscall.h>
#include <usloss.h>

#define CHECKMODE {						\
	if (psr_get() & PSR_CURRENT_MODE) { 				\
	    console("Trying to invoke syscall from kernel\n");	\
	    halt(1);						\
	}							\
}


/*
 *  Routine:  Spawn
 *
 *  Description: This is the call entry to fork a new user process.
 *
 *  Arguments:    char *name    -- new process's name
 *		  PFV func      -- pointer to the function to fork
 *		  void *arg	-- argument to function
 *                int stacksize -- amount of stack to be allocated
 *                int priority  -- priority of forked process
 *                int  *pid      -- pointer to output value
 *                (output value: process id of the forked process)
 *
 *  Return Value: 0 means success, -1 means error occurs
 *
 */
int Spawn(char *name, int (*func)(char *), char *arg, int stack_size, 
	int priority, int *pid)   
{
    sysargs sa;
    
    CHECKMODE;
    sa.number = SYS_SPAWN;
    sa.arg1 = (void *) func;
    sa.arg2 = arg;
    sa.arg3 = (void *) stack_size;
    sa.arg4 = (void *) priority;
    sa.arg5 = name;
    usyscall(&sa);
    *pid = (int) sa.arg1;
    return (int) sa.arg4;
} /* end of Spawn */


/*
 *  Routine:  Wait
 *
 *  Description: This is the call entry to wait for a child completion
 *
 *  Arguments:    int *pid -- pointer to output value 1
 *                (output value 1: process id of the completing child)
 *                int *status -- pointer to output value 2
 *                (output value 2: status of the completing child)
 *
 *  Return Value: 0 means success, -1 means error occurs
 *
 */
int Wait(int *pid, int *status)	
{
    sysargs sa;
    
    CHECKMODE;
    sa.number = SYS_WAIT;
    usyscall(&sa);
    *pid = (int) sa.arg1;
    *status = (int) sa.arg2;
    return (int) sa.arg4;
    
} /* End of Wait */


/*
 *  Routine:  Terminate
 *
 *  Description: This is the call entry to terminate 
 *               the invoking process and its children
 *
 *  Arguments:   int status -- the commpletion status of the process
 *
 *  Return Value: 0 means success, -1 means error occurs
 *
 */
void Terminate(int status)
{
    sysargs sa;
    
    CHECKMODE;
    sa.number = SYS_TERMINATE;
    sa.arg1 = (void *) status;
    usyscall(&sa);
    return;
    
} /* End of Terminate */


/*
 *  Routine:  SemCreate
 *
 *  Description: Create a semaphore.
 *		
 *
 *  Arguments:    int value -- initial semaphore value
 *		  int *semaphore -- semaphore handle
 *                (output value: completion status)
 *
 */
int SemCreate(int value, int *semaphore)
{
    sysargs sa;

    CHECKMODE;
    sa.number = SYS_SEMCREATE;
    sa.arg1 = (void *) value;
    usyscall(&sa);
    *semaphore = (int) sa.arg1;
    return (int) sa.arg4;
} /* end of SemCreate */


/*
 *  Routine:  SemP
 *
 *  Description: "P" a semaphore.
 *		
 *
 *  Arguments:    int semaphore -- semaphore handle
 *                (output value: completion status)
 *
 */
int SemP(int semaphore)
{
    sysargs sa;

    CHECKMODE;
    sa.number = SYS_SEMP;
    sa.arg1 = (void *) semaphore;
    usyscall(&sa);
    return (int) sa.arg4;
} /* end of SemP */


/*
 *  Routine:  SemV
 *
 *  Description: "V" a semaphore.
 *		
 *
 *  Arguments:    int semaphore -- semaphore handle
 *                (output value: completion status)
 *
 */
int SemV(int semaphore)
{
    sysargs sa;

    CHECKMODE;
    sa.number = SYS_SEMV;
    sa.arg1 = (void *) semaphore;
    usyscall(&sa);
    return (int) sa.arg4;
} /* end of SemV */


/*
 *  Routine:  SemFree
 *
 *  Description: Free a semaphore.
 *		
 *
 *  Arguments:    int semaphore -- semaphore handle
 *                (output value: completion status)
 *
 */
int SemFree(int semaphore)
{
    sysargs sa;

    CHECKMODE;
    sa.number = SYS_SEMFREE;
    sa.arg1 = (void *) semaphore;
    usyscall(&sa);
    return (int) sa.arg4;
} /* end of SemFree */


/*
 *  Routine:  GetTimeofDay
 *
 *  Description: This is the call entry point for getting the time of day.
 *
 *  Arguments:    int *tod  -- pointer to output value
 *                (output value: the time of day)
 *
 */
void GetTimeofDay(int *tod)                           
{
    sysargs sa;
    
    CHECKMODE;
    sa.number = SYS_GETTIMEOFDAY;
    usyscall(&sa);
    *tod = (int) sa.arg1;
    return;
} /* end of GetTimeofDay */


/*
 *  Routine:  CPUTime
 *
 *  Description: This is the call entry point for the process' CPU time.
 *		
 *
 *  Arguments:    int *cpu  -- pointer to output value
 *                (output value: the CPU time of the process)
 *
 */
void CPUTime(int *cpu)                           
{
    sysargs sa;

    CHECKMODE;
    sa.number = SYS_CPUTIME;
    usyscall(&sa);
    *cpu = (int) sa.arg1;
    return;
} /* end of CPUTime */


/*
 *  Routine:  GetPID
 *
 *  Description: This is the call entry point for the process' PID.
 *		
 *
 *  Arguments:    int *pid  -- pointer to output value
 *                (output value: the PID)
 *
 */
void GetPID(int *pid)                           
{
    sysargs sa;

    CHECKMODE;
    sa.number = SYS_GETPID;
    usyscall(&sa);
    *pid = (int) sa.arg1;
    return;
} /* end of GetPID */


/*
 *  Routine:  Sleep
 *
 *  Description: This is the call entry point for timed delay.
 *
 *  Arguments:    int seconds -- number of seconds to sleep
 *
 *  Return Value: 0 means success, -1 means error occurs
 *
 */
int Sleep(int seconds)
{
    sysargs sa;

    CHECKMODE;
    sa.number = SYS_SLEEP;
    sa.arg1 = (void *) seconds;
    usyscall(&sa);
    return (int) sa.arg4;
} /* end of Sleep */




/*
 *  Routine:  DiskRead
 *
 *  Description: This is the call entry point for disk input.
 *
 *  Arguments:    void* dbuff  -- pointer to the input buffer
 *                int   unit -- which disk to read
 *                int   track  -- first track to read
 *                int   first -- first sector to read
 *                int   sectors -- number of sectors to read
 *                int   *status    -- pointer to output value
 *                (output value: completion status)
 *
 *  Return Value: 0 means success, -1 means error occurs
 *
 */
int DiskRead(void *dbuff, int unit, int track, int first, int sectors,
    int *status)
{
    sysargs sa;

    CHECKMODE;
    sa.number = SYS_DISKREAD;
    sa.arg1 = dbuff;
    sa.arg2 = (void *) sectors;
    sa.arg3 = (void *) track;
    sa.arg4 = (void *) first;
    sa.arg5 = (void *) unit;
    usyscall(&sa);
    *status = (int) sa.arg1;
    return (int) sa.arg4;
} /* end of DiskRead */


/*
 *  Routine:  DiskWrite
 *
 *  Description: This is the call entry point for disk output.
 *
 *  Arguments:    void* dbuff  -- pointer to the output buffer
 *		  int   unit -- which disk to write
 *                int   track  -- first track to write
 *                int   first -- first sector to write
 *		  int	sectors -- number of sectors to write
 *                int   *status    -- pointer to output value
 *                (output value: completion status)
 *
 *  Return Value: 0 means success, -1 means error occurs
 *
 */
int DiskWrite(void *dbuff, int unit, int track, int first, int sectors, 
    int *status)
{
    sysargs sa;

    CHECKMODE;
    sa.number = SYS_DISKWRITE;
    sa.arg1 = dbuff;
    sa.arg2 = (void *) sectors;
    sa.arg3 = (void *) track;
    sa.arg4 = (void *) first;
    sa.arg5 = (void *) unit;
    usyscall(&sa);
    *status = (int) sa.arg1;
    return (int) sa.arg4;
} /* end of DiskWrite */


/*
 *  Routine:  DiskSize
 *
 *  Description: This is the call entry point for getting the disk size.
 *
 *  Arguments:    int	unit -- which disk
 *		  int	*sector -- # bytes in a sector
 *		  int	*track -- # sectors in a track
 *		  int   *disk -- # tracks in the disk
 *                (output value: completion status)
 *
 *  Return Value: 0 means success, -1 means error occurs
 *
 */
int DiskSize(int unit, int *sector, int *track, int *disk)
{
    sysargs sa;
    
    CHECKMODE;
    sa.number = SYS_DISKSIZE;
    sa.arg1 = (void *) unit;
    usyscall(&sa);
    *sector = (int) sa.arg1;
    *track = (int) sa.arg2;
    *disk = (int) sa.arg3;
    return (int) sa.arg4;
} /* end of DiskSize */

/* end libuser.c */
