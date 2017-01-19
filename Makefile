CC = gcc

INC = -I./udns -I./libev
CFLAGS = -g -fstack-protector-all -O3
LIBS = -lm
LD_LITEFLOW = ./libev/.libs/libev.a ./udns/libudns.a
TARGET_BIN = liteflow

LITEFLOW_OBJS = main.o \
				gen/version.o \
				liteflow.o \
				tcp.o \
				udp.o \
				litedt.o \
				retrans.o \
                ctrl.o \
				fec.o \
				hashqueue.o \
				rbuffer.o \
				config.o \
				stat.o \
				json.o

all: $(TARGET_BIN)
	@echo "All done"

gen/version.c: *.c *.h gen/.build
	rm -f $@.tmp
	echo '/* this file is auto-generated during build */' > $@.tmp
	echo '#include "../version.h"' >> $@.tmp
	echo 'const char* liteflow_version = ' >> $@.tmp
	if [ -d .git ]; then \
		echo '"liteflow.git/'`git describe --tags`'"'; \
		if [ `git status --porcelain | grep -v -c '^??'` != 0 ]; then \
			echo '"-unclean"'; \
		fi \
	else \
		echo '"liteflow/$(VERSION)"'; \
	fi >> $@.tmp
	echo ';' >> $@.tmp
	mv -f $@.tmp $@

gen/.build:
	mkdir -p gen
	touch $@


$(TARGET_BIN): $(LITEFLOW_OBJS) libev/.libs/libev.a udns/libudns.a
	$(CC) -o $@ $^ $(LIBS) $(LD_LITEFLOW)
	
%.o : %.c
	$(CC) -o $@ -c $< $(CFLAGS) $(INC)

libev/.libs/libev.a:
	cd libev && ./configure && make

udns/libudns.a:
	cd udns && ./configure && make

clean:
	rm -f *.o liteflow

distclean: clean
	-rm -rf ./gen
	-make -C ./udns distclean
	-make -C ./libev distclean
