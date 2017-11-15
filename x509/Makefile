CPP=g++
MYCURDIR=.
MY_UTILS_DIR=../utils
MY_X509_DIR=../x509
CFLAGS=-c -Wpointer-arith 
ifeq ($(DEBUG),1)
	CFLAGS+=-g
endif
CFLAGS+= -I$(MYCURDIR) -I$(MY_UTILS_DIR) -I$(MY_X509_DIR) -I/usr/include -I/usr/local/include -DAS_LIBRARY=1
AR=ar

SRCS=x509.cpp ca.cpp sslc.cpp ssls.cpp qmgmt.cpp

OBJECTS=x509.o ca.o  sslc.o ssls.o qmgmt.o

HEADERS=x509.hpp ca.hpp qmgmt.hpp

all: libx509.a

libx509.a: $(OBJECTS)
	$(AR) rcs libx509.a $(OBJECTS)

x509.o: x509.cpp $(HEADERS)
	$(CPP) $(CFLAGS) x509.cpp

ca.o: ca.cpp $(HEADERS)
	$(CPP) $(CFLAGS) ca.cpp

sslc.o: sslc.cpp $(HEADERS)
	$(CPP) $(CFLAGS) sslc.cpp

ssls.o: ssls.cpp $(HEADERS)
	$(CPP) $(CFLAGS) ssls.cpp

qmgmt.o: qmgmt.cpp $(HEADERS)
	$(CPP) $(CFLAGS) qmgmt.cpp

clean:
	rm -rf $(OBJECTS) libx509.a
