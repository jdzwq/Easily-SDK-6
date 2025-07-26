#-----------------------------------------------------------------------------
# begin GNU MAKE file
# making order:
# 1. make -f rtf.ar.mk test --if need to creating some directory or file-list
# 2. make -f rtf.ar.mk clean
# 3. make -f rtf.ar.mk
# 4. make -f rtf.ar.mk install
#-----------------------------------------------------------------------------
CC = clang
CFLAGS = -g -Wall -D _DEBUG

AR = ar
AFLAGS = -rcs

MODULE = rtf
ARCH = aarch64

SRV_PATH = /usr/local/xService
LNK_PATH = /usr/local/lib

INC_PATH = ../../include
SRC_PATH = ../../third-party
OUT_PATH = ../lib
OBJ_PATH = ../../../Easily-tmp/macos/$(MODULE)/$(ARCH)

TARGET = lib$(MODULE).a

DIRS = $(wildcard \
		$(SRC_PATH)/rtf/*.c)
SRCS = $(notdir $(DIRS))
COBS = $(patsubst %.c,%.o,$(SRCS))
OBJS = $(addprefix $(OBJ_PATH)/,$(COBS))

$(OBJ_PATH)/%.o : $(SRC_PATH)/rtf/%.c
	$(CC) $(CFLAGS) -c $< -o $@ -I $(INC_PATH)

all : $(OBJS)
	rm -f $@
	$(AR) $(AFLAGS) $(OUT_PATH)/$(TARGET) $(OBJS)
	ranlib -s $(OUT_PATH)/$(TARGET)
#	rm -f $(OBJS)

test:
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
#-----------------------------------------------------------------------------
# end GNU MAKE file
#-----------------------------------------------------------------------------