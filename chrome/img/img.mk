#-----------------------------------------------------------------------------
# begin GNU MAKE file
# making order:
# 1. nmake /f img.mk test --if need to creating some directory or file-list
# 2. nmake /f img.mk clean
# 3. nmake /f img.mk
# 4. nmake /f img.mk install
#-----------------------------------------------------------------------------
CC = gcc
CFLAGS = -g -Wall -fPIC -D _DEBUG

AR = ar
AFLAGS = -rcs

MODULE = img
ARCH = amd64

INC_PATH = ../../include
SRC_PATH = ../../third-party

OBJ_PATH = ~/Easily-temp/chrome/$(MODULE)/$(ARCH)

OUT_PATH = /usr/local/lib

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
	$(AR) $(AFLAGS) $(OBJ_PATH)/$(TARGET) $(OBJS)
	ranlib $(OBJ_PATH)/$(TARGET)

test:
	if ! test -d $(OBJ_PATH); then \
	mkdir -p $(OBJ_PATH); \
	chmod 755 $(OBJ_PATH); \
	fi
	
	@echo $(DIRS)
	@echo $(SRCS)
	@echo $(OBJS)

install:
	if ! test -d $(OUT_PATH); then \
	sudo mkdir -p $(OUT_PATH); \
	fi

	sudo cp -f $(OBJ_PATH)/$(TARGET) $(OUT_PATH);
	sudo chmod 644 $(OUT_PATH)/$(TARGET);

uninstall:
	sudo rm -r $(OUT_PATH)/$(TARGET);
	
.PHONY : clean
clean:
	rm -f $(OBJS)
	rm -f $(OBJ_PATH)/$(TARGET)
#-----------------------------------------------------------------------------
# end GNU MAKE file
#-----------------------------------------------------------------------------