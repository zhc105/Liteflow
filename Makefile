CC = gcc

INC =
CFLAGS = -g -fstack-protector-all -O0
LIBS = 

OBJS =  litedt.o \
        rbuffer.o \
        config.o

all : test_rbuffer test_litedt
	@echo "All done"

test_rbuffer : test_rbuffer.o $(OBJS)
	$(CC) -o $@ $^ $(LIBS)

test_litedt : test_litedt.o $(OBJS)
	$(CC) -o $@ $^ $(LIBS) -static
	
%.o : %.cpp
	$(CC) -o $@ -c $< $(CFLAGS) $(INC)

clean:
	rm -f *.o test_rbuffer test_litedt
