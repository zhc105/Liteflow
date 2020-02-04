CC          = gcc
INC         = -I./3rd/udns -I./3rd/libev -I./3rd/json-parser
CFLAGS      = -g -fstack-protector-all -O2 
LIBS        = -lm
LD_LITEFLOW = ./3rd/libev/.libs/libev.a ./3rd/udns/libudns.a ./3rd/json-parser/libjsonparser.a
TARGET_BIN  = liteflow

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
				stat.o 

all: $(TARGET_BIN)
	@echo "All done"

static: $(TARGET_BIN)-static
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


$(TARGET_BIN): $(LITEFLOW_OBJS) 3rd/libev/.libs/libev.a 3rd/udns/libudns.a 3rd/json-parser/libjsonparser.a
	$(CC) -o $@ $^ $(LD_LITEFLOW) $(LIBS)

$(TARGET_BIN)-static: $(LITEFLOW_OBJS) 3rd/libev/.libs/libev.a 3rd/udns/libudns.a 3rd/json-parser/libjsonparser.a
	$(CC) -o $@ $^ $(LD_LITEFLOW) $(LIBS) -static
	mv $@ $(TARGET_BIN)
	
%.o : %.c
	$(CC) -o $@ -c $< $(CFLAGS) $(INC)

3rd/libev/.libs/libev.a:
	cd 3rd/libev && bash ./autogen.sh && ./configure && make

3rd/udns/libudns.a:
	cd 3rd/udns && ./configure && make

3rd/json-parser/libjsonparser.a:
	cd 3rd/json-parser && ./configure && make

clean:
	rm -f *.o liteflow

distclean: clean
	-rm -rf ./gen
	-make -C ./test clean
	-make -C ./3rd/udns distclean
	-make -C ./3rd/libev distclean
	-make -C ./3rd/json-parser clean
