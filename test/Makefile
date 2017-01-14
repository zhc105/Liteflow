CC = gcc

INC = -I../
CFLAGS = -g -fstack-protector-all -O0
LIBS = -lm

TEST_RBUFFER_OBJS = test_rbuffer.o \
                    ../rbuffer.o

TEST_HASHQUEUE_OBJS =	test_hashqueue.o \
						../hashqueue.o 

TEST_LITEDT_OBJS =  test_litedt.o \
                    ../litedt.o \
                    ../retrans.o \
                    ../fec.o \
                    ../hashqueue.o \
                    ../rbuffer.o \
                    ../config.o \
                    ../json.o

all: test_rbuffer test_hashqueue test_litedt
	@echo "All done"

test_rbuffer : $(TEST_RBUFFER_OBJS)
	$(CC) -o $@ $^ $(LIBS)

test_hashqueue: $(TEST_HASHQUEUE_OBJS)
	$(CC) -o $@ $^ $(LIBS)

test_litedt : $(TEST_LITEDT_OBJS)
	$(CC) -o $@ $^ $(LIBS) 
	
%.o : %.c
	$(CC) -o $@ -c $< $(CFLAGS) $(INC)

clean:
	rm -f *.o test_rbuffer test_litedt test_hashqueue
