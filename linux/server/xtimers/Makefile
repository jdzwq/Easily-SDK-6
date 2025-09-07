#-----------------------------------------------------------------------------
# begin GNU MAKE file
# making order:
# 1. nmake /f xtimers.so.mk test --if need to creating some directory or file-list
# 2. nmake /f xtimers.so.mk clean
# 3. nmake /f xtimers.so.mk
# 4. nmake /f xtimers.so.mk install
#-----------------------------------------------------------------------------
CC = gcc
CFLAGS = -g -Wall -D _DEBUG

MODULE = xtimers
ARCH = aarch64

LIB_PATH = /usr/local/lib

INC_PATH = ~/Easily-sdk-6/include
SRC_PATH = ~/Easily-sdk-6/server
OBJ_PATH = ~/Easily-tmp/linux/$(MODULE)/$(ARCH)
OUT_PATH = ~/Easily-app-6/linux/bin

DIRS = $(wildcard \
	$(SRC_PATH)/xtimers/*.cc \
	$(SRC_PATH)/*.cc)
SRCS = $(notdir $(DIRS))
COBS = $(patsubst %.cc, %.o, $(SRCS))
OBJS = $(addprefix $(OBJ_PATH)/,$(COBS))

$(OBJ_PATH)/%.o : $(SRC_PATH)/xtimers/%.cc
	$(CC) $(CFLAGS) -c $< -o $@ -I $(INC_PATH)

$(OBJ_PATH)/%.o : $(SRC_PATH)/%.cc
	$(CC) $(CFLAGS) -c $< -o $@ -I $(INC_PATH)

all : $(OBJS)
	rm -f $@
	$(CC) -o $(OUT_PATH)/$(MODULE) $(OBJS) -L $(LIB_PATH) -lxdk -lxdn -lxdg -lxdl

test:
	if ! test -d $(OBJ_PATH); then \
	mkdir -p $(OBJ_PATH); \
	chmod 755 $(OBJ_PATH); \
	fi
	@echo $(DIRS)
	@echo $(SRCS)
	@echo $(OBJS)

.PHONY : clean
clean:
	rm -f $(OBJS)
	rm -f $(OUT_PATH)/$(MODULE)
#-----------------------------------------------------------------------------
# end GNU MAKE file
#-----------------------------------------------------------------------------
