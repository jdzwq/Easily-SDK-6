#-----------------------------------------------------------------------------
# begin GNU MAKE file
# making order for release version:
# 1. make -test
# 2. make clean
# 3. make all
# 4. make install
#-----------------------------------------------------------------------------
CC = clang
CFLAGS = -g -Wall

MODULE = xtimers
ARCH = aarch64

LIB_PATH = /usr/local/lib
SRV_PATH = /usr/local/Easily/sbin

INC_PATH = ../../../include
SRC_PATH = ../../../server

OBJ_PATH = ~/工程/Easily-temp/macos/$(MODULE)/$(ARCH)

DIRS = $(wildcard \
	$(SRC_PATH)/xtimers/*.cc \
	$(SRC_PATH)/*.cc)
SRCS = $(notdir $(DIRS))
COBS = $(patsubst %.cc, %.o, $(SRCS))
OBJS = $(addprefix $(OBJ_PATH)/,$(COBS))

$(OBJ_PATH)%.o : $(SRC_PATH)/xtimers/%.cc
	$(CC) $(CFLAGS) -c $< -o $@ -I $(INC_PATH)

$(OBJ_PATH)%.o : $(SRC_PATH)/%.cc
	$(CC) $(CFLAGS) -c $< -o $@ -I $(INC_PATH)

all : $(OBJS)
	rm -f $@
	$(CC) -o $(OBJ_PATH)/$(MODULE) $(OBJS) -L $(LIB_PATH) -lxdk -lxdg -lxdl \
	-Wl,-rpath $(LIB_PATH)

test:
	if ! test -d $(OBJ_PATH); then \
	mkdir -p $(OBJ_PATH); \
	chmod 755 $(OBJ_PATH); \
	fi

	@echo $(DIRS)
	@echo $(SRCS)
	@echo $(OBJS)

install:
	if ! test -d $(SRV_PATH); then \
	sudo mkdir $(SRV_PATH); \
	fi

	sudo cp -f $(OBJ_PATH)/$(MODULE) $(SRV_PATH);
	sudo chmod +x $(SRV_PATH)/$(MODULE);

uninstall:
	sudo rm -f $(SRV_PATH)/$(MODULE)

.PHONY : clean
clean:
	rm -f $(OBJS)
	rm -f $(OBJ_PATH)/$(MODULE)
#-----------------------------------------------------------------------------
# end GNU MAKE file
#-----------------------------------------------------------------------------
