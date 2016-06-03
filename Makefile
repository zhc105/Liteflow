CC = gcc

INC = -I./udns
CFLAGS = -g -fstack-protector-all -O0
LIBS = -lm
LD_LITEFLOW = ./libev/.libs/libev.a ./udns/libudns.a

LITEFLOW_OBJS = main.o \
                liteflow.o \
                litedt.o \
                rbuffer.o \
                config.o \
                stat.o \
                json.o

TEST_RBUFFER_OBJS = test_rbuffer.o \
                    rbuffer.o

TEST_LITEDT_OBJS =  test_litedt.o \
                    litedt.o \
                    rbuffer.o \
                    config.o \
                    json.o

all: liteflow test_rbuffer test_litedt
	@echo "All done"

liteflow: $(LITEFLOW_OBJS)
	$(CC) -o $@ $^ $(LIBS) $(LD_LITEFLOW)

test_rbuffer : $(TEST_RBUFFER_OBJS)
	$(CC) -o $@ $^ $(LIBS)

test_litedt : $(TEST_LITEDT_OBJS)
	$(CC) -o $@ $^ $(LIBS)
	
%.o : %.c
	$(CC) -o $@ -c $< $(CFLAGS) $(INC)

clean:
	rm -f *.o liteflow test_rbuffer test_litedt
