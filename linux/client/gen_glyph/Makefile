#-----------------------------------------------------------------------------
# begin GNU MAKE file
# making order:
# 1. make -f Makefile.mk test --if need to creating some directory or file-list
# 2. make -f Makefile.mk clean
# 3. make -f Makefile.mk
# 4. make -f Makefile.mk install
#-----------------------------------------------------------------------------
CC = gcc
CFLAGS = -g -Wall -D _DEBUG

MODULE = gen_glyph
ARCH = aarch64

LIB_PATH = /usr/local/lib

INC_PATH = ~/Easily-sdk-6/include
SRC_PATH = ~/Easily-sdk-6/client/gen_glyph
OBJ_PATH = ~/Easily-tmp/linux/$(MODULE)/$(ARCH)
OUT_PATH = ~/Easily-app-6/linux/bin

DIRS = $(wildcard $(SRC_PATH)/gen_system.cc)
SRCS = $(notdir $(DIRS))
COBS = $(patsubst %.cc, %.o, $(SRCS))
OBJS = $(addprefix $(OBJ_PATH)/,$(COBS))

$(OBJ_PATH)/%.o : $(SRC_PATH)/%.cc
	$(CC) $(CFLAGS) -c $< -o $@ -I $(INC_PATH)

all : $(OBJS)
	rm -f $@
	$(CC) -o $(OUT_PATH)/$(MODULE) $(OBJS) -L $(LIB_PATH) -lxdk -lxdn -lxdg -lxdu

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
