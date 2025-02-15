CC = gcc
CFLAGS = -g -Wall -fPIC

SRV_PATH = /usr/local/xService
LNK_PATH = /usr/local/lib

VER = 6.0
INC_PATH = ../../include
SRC_PATH = ../../xdl
OUT_PATH = ~/Easily-app-6/linux/sbin/api

LIBS = -lm -L $(LNK_PATH) -lxdk
DIRS = $(wildcard \
	$(SRC_PATH)/*.c \
	$(SRC_PATH)/linux/*.c \
	$(SRC_PATH)/bag/*.c \
	$(SRC_PATH)/bio/*.c \
	$(SRC_PATH)/doc/*.c \
	$(SRC_PATH)/gdi/*.c \
	$(SRC_PATH)/hint/*.c \
	$(SRC_PATH)/ing/*.c \
	$(SRC_PATH)/mis/*.c \
	$(SRC_PATH)/par/*.c \
	$(SRC_PATH)/scan/*.c \
	$(SRC_PATH)/tio/*.c \
	$(SRC_PATH)/view/*.c \
	$(SRC_PATH)/xdb/*.c)
SRCS = $(notdir $(DIRS))
OBJS = $(patsubst %.c, %.o, $(SRCS))
MODULE = libxdl.so
TARGET = $(OUT_PATH)/$(MODULE).$(VER)

%.o : $(SRC_PATH)/%.c
	$(CC) $(CFLAGS) -c $< -o $@ -I $(INC_PATH)

%.o : $(SRC_PATH)/linux/%.c
	$(CC) $(CFLAGS) -c $< -o $@ -I $(INC_PATH)

%.o : $(SRC_PATH)/bag/%.c
	$(CC) $(CFLAGS) -c $< -o $@ -I $(INC_PATH)

%.o : $(SRC_PATH)/bio/%.c
	$(CC) $(CFLAGS) -c $< -o $@ -I $(INC_PATH)

%.o : $(SRC_PATH)/doc/%.c
	$(CC) $(CFLAGS) -c $< -o $@ -I $(INC_PATH)

%.o : $(SRC_PATH)/gdi/%.c
	$(CC) $(CFLAGS) -c $< -o $@ -I $(INC_PATH)

%.o : $(SRC_PATH)/hint/%.c
	$(CC) $(CFLAGS) -c $< -o $@ -I $(INC_PATH)

%.o : $(SRC_PATH)/ing/%.c
	$(CC) $(CFLAGS) -c $< -o $@ -I $(INC_PATH)

%.o : $(SRC_PATH)/mis/%.c
	$(CC) $(CFLAGS) -c $< -o $@ -I $(INC_PATH)

%.o : $(SRC_PATH)/par/%.c
	$(CC) $(CFLAGS) -c $< -o $@ -I $(INC_PATH)

%.o : $(SRC_PATH)/scan/%.c
	$(CC) $(CFLAGS) -c $< -o $@ -I $(INC_PATH)

%.o : $(SRC_PATH)/tio/%.c
	$(CC) $(CFLAGS) -c $< -o $@ -I $(INC_PATH)

%.o : $(SRC_PATH)/view/%.c
	$(CC) $(CFLAGS) -c $< -o $@ -I $(INC_PATH)

%.o : $(SRC_PATH)/xdb/%.c
	$(CC) $(CFLAGS) -c $< -o $@ -I $(INC_PATH)

all : $(OBJS)
	rm -f $@
	$(CC) -shared -fPIC -pthread -o $(TARGET) $(OBJS) $(LIBS)
	rm -f $(OBJS)

test:
	@echo $(DIRS)
	@echo $(SRCS)
	@echo $(OBJS)

install:
	if ! test -d $(SRV_PATH); then \
	sudo mkdir $(SRV_PATH); \
	fi
	if ! test -d $(SRV_PATH)/api; then \
	sudo mkdir $(SRV_PATH)/api; \
	fi

	sudo cp -f $(TARGET) $(SRV_PATH)/api;
	sudo chmod +x $(SRV_PATH)/api/$(MODULE).$(VER);
	sudo rm -f $(LNK_PATH)/libxdl*;
	sudo ln -bs $(SRV_PATH)/api/$(MODULE).$(VER) $(LNK_PATH)/$(MODULE);

uninstall:
	sudo rm -r $(LNK_PATH)/$(MODULE)*;
	sudo rm -f $(SRV_PATH)/api/$(MODULE).$(VER)
	
.PHONY : clean
clean:
	-rm -f $(OBJS)
