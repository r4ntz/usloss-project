TARGET=libphase4.a
ASSIGNMENT=452phase4
CC=gcc
AR=ar
COBJS= phase4.o libuser.o p1.o 
CSRCS=${COBJS:.o=.c}
HDRS= server.h
INCLUDE = ./usloss/include
CFLAGS = -Wall -g -I${INCLUDE} -I. -Wno-int-to-pointer-cast -Wno-pointer-to-int-cast

LDFLAGS = -L. -L./usloss/lib
TESTDIR=testcases

TESTS= test00 test01 test02 test03 test04 test05 test06 test07 test08 \
       test09 test10 test11 test12 

LIBS = -llxuphase3 -llxuphase2 -llxuphase1 -lusloss \
       -llxuphase1 -llxuphase2 -llxuphase3 -lphase4 


$(TARGET):	$(COBJS)
		$(AR) -r $@ $(COBJS) 

$(TESTS):	$(TARGET)  
	$(CC) $(CFLAGS) -c $(TESTDIR)/$@.c
	$(CC) $(LDFLAGS) -o $@ $@.o $(LIBS) 
clean:
	rm -f $(COBJS) $(TARGET) test*.o term*.out p1.o $(TESTS) core


phase4.o:	driver.h



