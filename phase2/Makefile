TARGET=libphase2.a
ASSIGNMENT= 452phase2
CC=gcc
AR=ar
COBJS= phase2.o
CSRCS=${COBJS:.o=.c}
HDRS=message.h

INCLUDE = ./usloss/include
CFLAGS = -Wall -g -I${INCLUDE} -I.


LDFLAGS = -L. -L./usloss/lib

TESTDIR=testcases
TESTS= test00 test01 test02 test03 test04 test05 test06 test07 test08 \
       test09 test10 test11 test12 test13 test14 test15 test16 test17 \
       test18 test19 test20 test21 test22 test23 test24 test25 test26 \
       test27 test28 test29 test30 test31 test32 test33 test34 test35 \
       test36 test37 test38 test39 test40 test41 test42
PHASE1LIB = lxuphase1
LIBS = -l${PHASE1LIB} -lphase2 -lusloss -l${PHASE1LIB}
$(TARGET):	$(COBJS)
		$(AR) -r $@ $(COBJS) 

$(TESTS):	$(TARGET) p1.o
	$(CC) $(CFLAGS) -c $(TESTDIR)/$@.c
	$(CC) $(LDFLAGS) -o $@ $@.o $(LIBS) p1.o

clean:
	rm -f $(COBJS) $(TARGET) core term*.out test*.o $(TESTS) p1.o

phase2.o:	message.h
	$(CC) $(CFLAGS) -c phase2.c


