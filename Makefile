CC=gcc
CFLAGS=-g -Wall -O2
LDFLAGS=-lcjson -lxdp -lbpf -lpthread -lz

SRCS=./src/xfw_user.c ./src/xfw_rules.c
OBJS=$(SRCS:.c=.o)
BIN_FW=./xfw_user
TARGET=./src/$(BIN_FW)

BPF_CLANG=clang

KERN_DIR=/lib/modules/$(shell uname -r)/build
BPF_PATH=./xfw_kern.o
BPF_OBJ=./src/$(BPF_PATH)
BPF_SRC=./src/xfw_kern.c

all: $(TARGET) $(BPF_OBJ) install

$(TARGET): $(OBJS)
	$(CC) -o $@ $^ $(LDFLAGS)

$(BPF_OBJ): $(BPF_SRC)
	$(BPF_CLANG) -O2 -g -Wall -target bpf -c $< -o $@

clean:
	rm -f $(OBJS) $(BIN_FW) $(TARGET) $(BPF_OBJ) $(BPF_PATH)

install:
	cp -dpr $(TARGET) ./$(BIN_FW)
	cp -dpr $(BPF_OBJ) ./$(BPF_PATH)
