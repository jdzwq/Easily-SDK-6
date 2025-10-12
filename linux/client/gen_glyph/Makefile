#-----------------------------------------------------------------------------
# begin GNU MAKE file
# making order for release version:
# 1. make test
# 2. make clean
# 3. make all
# 4. make install
#-----------------------------------------------------------------------------
CC = gcc
CFLAGS = -g -Wall

MODULE = gen_glyph
ARCH = aarch64

LIB_PATH = /usr/local/lib
CLI_PATH = /usr/local/Easily/bin

INC_PATH = ../../../include
SRC_PATH = ../../../client

OBJ_PATH = ~/Easily-temp/linux/$(MODULE)/$(ARCH)

DIRS = $(wildcard $(SRC_PATH)/gen_glyph/gen_system.cc)
SRCS = $(notdir $(DIRS))
COBS = $(patsubst %.cc, %.o, $(SRCS))
OBJS = $(addprefix $(OBJ_PATH)/,$(COBS))

$(OBJ_PATH)/%.o : $(SRC_PATH)/gen_glyph/%.cc
	$(CC) $(CFLAGS) -c $< -o $@ -I $(INC_PATH)

all : $(OBJS)
	rm -f $@
	$(CC) -o $(OBJ_PATH)/$(MODULE) $(OBJS) -L $(LIB_PATH) -lxdk -lxdg -lxdu

test:
	if ! test -d $(OBJ_PATH); then \
	mkdir -p $(OBJ_PATH); \
	chmod 755 $(OBJ_PATH); \
	fi
	@echo $(DIRS)
	@echo $(SRCS)
	@echo $(OBJS)

install:
	if ! test -d $(CLI_PATH); then \
	sudo mkdir $(CLI_PATH); \
	fi

	sudo cp -f $(OBJ_PATH)/$(MODULE) $(CLI_PATH);
	sudo chmod +x $(CLI_PATH)/$(MODULE);

uninstall:
	sudo rm -f $(CLI_PATH)/$(MODULE)

.PHONY : clean
clean:
	rm -f $(OBJS)
	rm -f $(OBJ_PATH)/$(MODULE)
#-----------------------------------------------------------------------------
# end GNU MAKE file
#-----------------------------------------------------------------------------
