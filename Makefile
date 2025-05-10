# Output binary name
bin=coin-server

# Set the following to '0' to disable log messages:
LOGGER ?= 1
DEBUG_ON ?= 0
VERSION = 2.0

# Compiler/linker flags
CFLAGS += -g -Wall -pthread -I/usr/include/protobuf-c -DLOGGER=$(LOGGER) -DVERSION=$(VERSION) -DDEBUG_ON=$(DEBUG_ON)
LDLIBS += -lprotobuf-c 
LDFLAGS +=

src=server.c common.c task.c sha1.c coin.pb-c.c
obj=$(src:.c=.o)

all: $(bin)

$(bin): $(obj)
	$(CC) $(CFLAGS) $(LDLIBS) $(LDFLAGS) $(obj) -o $@

server.o: server.c server.h common.h coin.pb-c.h
common.o: common.c common.h logger.h
task.o:   task.c   task.h   logger.h
sha1.o:   sha1.c   sha1.h
coin.pb-c.o: coin.pb-c.c coin.pb-c.h


clean:
	rm -f $(bin) $(obj) vgcore.*

