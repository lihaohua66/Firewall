#akefile

all: test1 test1M
.PHONY: all
CC = g++
OBJ1 = test1.o firewall.o
OBJ2 = test1M.o firewall.o

test1: $(OBJ1)
	$(CC) -o test1 $(OBJ1) 
test1M: $(OBJ2)
	$(CC) -o test1M $(OBJ2)

test1.o: test1.cpp
	$(CC) -c test1.cpp
test1M.o: test1M.cpp	
	$(CC) -c test1M.cpp
firewall.o: firewall.cpp
	$(CC) -c firewall.cpp

.PHONiY: clean
clean:
	-rm test1 test1M *.o
