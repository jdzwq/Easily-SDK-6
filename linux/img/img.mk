#-----------------------------------------------------------------------------
# begin GNU MAKE file
# making order for debug version:
# 1. make -f img.mk test --if need to creating some directory or file-list
# 2. make -f img.mk clean
# 3. make -f img.mk
# 4. make -f img.mk install
#-----------------------------------------------------------------------------
CC = gcc
CFLAGS = -g -Wall -fPIC -D _DEBUG

AR = ar
AFLAGS = -rcs

MODULE = img
ARCH = aarch64

SRV_PATH = /usr/local/Easily/sbin
LNK_PATH = /usr/local/lib

INC_PATH = ../../include
SRC_PATH = ../../third-party

OUT_PATH = ../lib
OBJ_PATH = ~/Easily-temp/linux/$(MODULE)/$(ARCH)

TARGET = lib$(MODULE).a

DIRS = $(wildcard \
		$(SRC_PATH)/jpg/*.c \
		$(SRC_PATH)/png/*.c \
		$(SRC_PATH)/zlib/*.c)
SRCS = $(notdir $(DIRS))
COBS = $(patsubst %.c,%.o,$(SRCS))
OBJS = $(addprefix $(OBJ_PATH)/,$(COBS))

$(OBJ_PATH)/%.o : $(SRC_PATH)/jpg/%.c
	$(CC) $(CFLAGS) -c $< -o $@ -I $(INC_PATH)

$(OBJ_PATH)/%.o : $(SRC_PATH)/png/%.c
	$(CC) $(CFLAGS) -c $< -o $@ -I $(INC_PATH)

$(OBJ_PATH)/%.o : $(SRC_PATH)/zlib/%.c
	$(CC) $(CFLAGS) -c $< -o $@ -I $(INC_PATH)

all : $(OBJS)
	rm -f $@
	$(AR) $(AFLAGS) $(OUT_PATH)/$(TARGET) $(OBJS)
	ranlib $(OUT_PATH)/$(TARGET)

test:
	if ! test -d $(OUT_PATH); then \
	mkdir -p $(OUT_PATH); \
	chmod 755 $(OUT_PATH); \
	fi
	
	if ! test -d $(OBJ_PATH); then \
	mkdir -p $(OBJ_PATH); \
	chmod 755 $(OBJ_PATH); \
	fi
	@echo $(DIRS)
	@echo $(SRCS)
	@echo $(OBJS)

install:
	if ! test -d $(LNK_PATH); then \
	sudo mkdir -p $(LNK_PATH); \
	fi

	sudo cp -f $(OUT_PATH)/$(TARGET) $(LNK_PATH);
	sudo chmod 644 $(LNK_PATH)/$(TARGET);

uninstall:
	sudo rm -r $(LNK_PATH)/$(TARGET);
	
.PHONY : clean
clean:
	rm -f $(OBJS)
	rm -f $(OUT_PATH)/$(TARGET)
#-----------------------------------------------------------------------------
# end GNU MAKE file
#-----------------------------------------------------------------------------