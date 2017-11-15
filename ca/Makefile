CC=gcc
CPP=g++
MYCURDIR=.
MY_UTILS_DIR=../utils
MY_X509_DIR=../x509

CPPFLAGS=-c -Wpointer-arith 
ifeq ($(DEBUG),1)
	CPPFLAGS+=-g
else
    DEBUG=0
endif
CPPFLAGS+= -I$(MYCURDIR) -I$(MY_X509_DIR) -I$(MY_UTILS_DIR) -I/usr/include 

CFLAGS=-c -Wpointer-arith 
ifeq ($(DEBUG),1)
	CFLAGS+=-g
else
    DEBUG=0
endif

CFLAGS+= -I$(MYCURDIR) -I$(MY_X509_DIR) -I$(MY_UTILS_DIR) -I/usr/include 
LDADD= -lcrypto -lssl -lpthread -lx509 -lutils -levent -levent_core -levent_extra -levent_openssl -levent_pthreads -lssl -lcrypto -ldl
LDADD+= -L$(MY_X509_DIR) -L/usr/lib -L$(MY_UTILS_DIR)

SRCS_ROOTCA=rootca.cpp 
OBJECTS_ROOTCA=rootca.o
HEADERS=policy.h 

UTILS_LIB=$(MY_UTILS_DIR)/libutils.a
X509_LIB=$(MY_X509_DIR)/libx509.a

ALLPROGS=rootca

all:$(ALLPROGS) 

$(UTILS_LIB):
	make DEBUG=$(DEBUG) -C $(MY_UTILS_DIR)

$(X509_LIB):
	make DEBUG=$(DEBUG) -C $(MY_X509_DIR)

rootca: $(OBJECTS_ROOTCA) $(UTILS_LIB) $(X509_LIB)
	$(CPP) $(OBJECTS_ROOTCA) -o rootca $(LDADD)

rootca.o: rootca.cpp $(HEADERS)
	$(CPP) $(CPPFLAGS) rootca.cpp

clean:
	make -C $(MY_UTILS_DIR) clean
	make -C $(MY_X509_DIR) clean
	rm -rf $(OBJECTS_ROOTCA) rootca 
