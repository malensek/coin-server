# Output binary name
bin=coin-server

# Set the following to '0' to disable log messages:
LOGGER ?= 1
DEBUG_ON ?= 0
VERSION = 2.0

# Compiler/linker flags
CFLAGS += -g -Wall -pthread -I/usr/include/protobuf-c \
	  -DLOGGER=$(LOGGER) -DVERSION=$(VERSION) -DDEBUG_ON=$(DEBUG_ON)
LDLIBS += -lprotobuf-c 
LDFLAGS +=

src=server.c common.c task.c sha1.c coin-messages.pb-c.c user_manager.c
obj=$(src:.c=.o)

all: $(bin)

$(bin): $(obj)
	$(CC) $(CFLAGS) $(LDLIBS) $(LDFLAGS) $(obj) -o $@

proto_out=coin-messages.pb-c.h coin-messages.pb-c.c \
	  ./demo-client/coin_messages_pb2.py
$(proto_out): coin-messages.proto
	protoc coin-messages.proto --c_out=./
	protoc coin-messages.proto --python_out=./demo-client

server.o: server.h server.c common.o logger.h coin-messages.pb-c.h
common.o: common.h logger.h coin-messages.pb-c.h
task.o: task.h task.c logger.h
sha1.o: sha1.c sha1.h
user_manager.o: user_manager.c user_manager.h
coin-messages.pb-c.o: coin-messages.pb-c.c coin-messages.pb-c.h coin-messages.proto

clean:
	rm -f $(bin) $(obj) $(proto_out) vgcore.*
