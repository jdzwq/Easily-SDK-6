#-----------------------------------------------------------------------------
# begin GNU MAKE file
# making order for release version:
# 1. make clean
# 2. make
# 3. make install
#-----------------------------------------------------------------------------
CC = clang
CFLAGS = -g -Wall
AR = ar
AFLAGS = -rcs

MODULE = bar
ARCH = aarch64

SRV_PATH = /usr/local/Easily/sbin
LNK_PATH = /usr/local/lib

INC_PATH = ../../include
SRC_PATH = ../../third-party

OUT_PATH = ../lib
OBJ_PATH = ~/工程/Easily-temp/macos/$(MODULE)/$(ARCH)

TARGET = lib$(MODULE).a

DIRS = $(wildcard \
		$(SRC_PATH)/bar/*.c)
SRCS = $(notdir $(DIRS))
COBS = $(patsubst %.c,%.o,$(SRCS))
OBJS = $(addprefix $(OBJ_PATH)/,$(COBS))

$(OBJ_PATH)/%.o : $(SRC_PATH)/bar/%.c
	$(CC) $(CFLAGS) -c $< -o $@ -I $(INC_PATH)

all : $(OBJS)
	rm -f $@
	$(AR) $(AFLAGS) $(OUT_PATH)/$(TARGET) $(OBJS)
	ranlib -s $(OUT_PATH)/$(TARGET)

test:
	if ! test -d $(OBJ_PATH); then \
	mkdir -p $(OBJ_PATH); \
	chmod 755 $(OBJ_PATH); \
	fi

	if ! test -d $(OUT_PATH); then \
	mkdir -p $(OUT_PATH); \
	chmod 644 $(OUT_PATH); \
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