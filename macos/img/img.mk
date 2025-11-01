#-----------------------------------------------------------------------------
# begin GNU MAKE file
# making order for debug version:
# 1. make -f img.mk test --if need to creating some directory or file-list
# 2. make -f img.mk clean
# 3. make -f img.mk
# 4. make -f img.mk install
#-----------------------------------------------------------------------------
CC = clang
CFLAGS = -std=c11 -g -Wall -D _DEBUG

AR = ar
AFLAGS = -rcs

MODULE = img
ARCH = aarch64

LIB_PATH = /usr/local/lib

INC_PATH = ../../include
SRC_PATH = ../../third-party

OBJ_PATH = ~/工程/Easily-temp/macos/$(MODULE)/$(ARCH)

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
	$(AR) $(AFLAGS) $(OBJ_PATH)/$(TARGET) $(OBJS)
	ranlib -s $(OBJ_PATH)/$(TARGET)

test:
	if ! test -d $(OBJ_PATH); then \
	mkdir -p $(OBJ_PATH); \
	chmod 755 $(OBJ_PATH); \
	fi

	@echo $(DIRS)
	@echo $(SRCS)
	@echo $(OBJS)

install:
	if ! test -d $(LIB_PATH); then \
	sudo mkdir -p $(LIB_PATH); \
	fi

	sudo cp -f $(OBJ_PATH)/$(TARGET) $(LIB_PATH);
	sudo chmod 644 $(LIB_PATH)/$(TARGET);

uninstall:
	sudo rm -r $(LIB_PATH)/$(TARGET);
	
.PHONY : clean
clean:
	rm -f $(OBJS)
	rm -f $(OBJ_PATH)/$(TARGET)
#-----------------------------------------------------------------------------
# end GNU MAKE file
#-----------------------------------------------------------------------------