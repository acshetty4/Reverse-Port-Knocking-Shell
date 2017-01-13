#CC = g++44 -std=c++0x
CC = g++ -std=c++0x
OPT = -O3
WARN = -Wall
ERR = -Werror

CFLAGS = $(OPT) $(WARN) $(ERR)

BCKDR_SRC = backdoor.cpp
BCKDR_OBJ = backdoor.o

KCKR_SRC = knocker.cpp
KCKR_OBJ = knocker.o

all:bck kck

bck: $(BCKDR_OBJ)
	$(CC) -o backdoor $(CFLAGS) $(BCKDR_OBJ) -lm -lpcap -lcurl -lcurlpp
	
kck: $(KCKR_OBJ)
	$(CC) -o knocker $(CFLAGS) $(KCKR_OBJ) -lm
	
.cc.o:
	$(CC) $(CFLAGS)  -c $*.cpp

clean:
	rm -f *.o bck
	rm -f *.o kck
