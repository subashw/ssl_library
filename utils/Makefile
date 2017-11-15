CC=gcc
MYCURDIR=.
CFLAGS=-c -Wpointer-arith 
ifeq ($(DEBUG),1)
        CFLAGS+=-g
endif
CFLAGS+= -I$(MYCURDIR) -I/usr/include 
CFLAGS+= -DAS_LIBRARY=1
AR=ar

SRCS=int.c net.cpp stream.cpp

OBJECTS=ini.o net.o stream.o

HEADERS=ini.h  net.h stream.h

all: libutils.a

libutils.a: $(OBJECTS)
	$(AR) rcs libutils.a $(OBJECTS)

ini.o: ini.c $(HEADERS)
	$(CC) $(CFLAGS) ini.c

net.o: net.cpp $(HEADERS)
	$(CC) $(CFLAGS) net.cpp

stream.o: stream.cpp $(HEADERS)
	$(CC) $(CFLAGS) stream.cpp

clean:
	rm -rf $(OBJECTS) libutils.a
