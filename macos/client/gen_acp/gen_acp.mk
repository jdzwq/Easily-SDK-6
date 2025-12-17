#-----------------------------------------------------------------------------
# begin GNU MAKE file
# making order for debug version:
# 1. make -f gen_acp.mk tools --if need to creating some directory or file-list
# 2. make -f gen_acp.mk clean
# 3. make -f gen_acp.mk
# 4. make -f gen_acp.mk install
#-----------------------------------------------------------------------------
CC = clang
CFLAGS = -g -Wall -D _DEBUG

MODULE = gen_acp
ARCH = aarch64

LIB_PATH = /usr/local/lib

INC_PATH = ../../../include
SRC_PATH = ../../../client

OBJ_PATH = ~/工程/Easily-temp/macos/$(MODULE)/$(ARCH)
OUT_PATH = ~/工程/Easily-app-6/macos/bin

DIRS = $(wildcard $(SRC_PATH)/gen_acp/*.cc)
SRCS = $(notdir $(DIRS))
COBS = $(patsubst %.cc, %.o, $(SRCS))
OBJS = $(addprefix $(OBJ_PATH)/,$(COBS))

$(OBJ_PATH)/%.o : $(SRC_PATH)/gen_acp/%.cc
	$(CC) $(CFLAGS) -c $< -o $@ -I $(INC_PATH)

all : $(OBJS)
	rm -f $@
	$(CC) -o $(OBJ_PATH)/$(MODULE) $(OBJS) -L $(LIB_PATH) -lxdk \
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
	if ! test -d $(OUT_PATH); then \
	mkdir $(OUT_PATH); \
	fi

	cp -f $(OBJ_PATH)/$(MODULE) $(OUT_PATH);
	chmod +x $(OUT_PATH)/$(MODULE);

uninstall:
	rm -f $(OUT_PATH)/$(MODULE)

.PHONY : clean
clean:
	rm -f $(OBJS)
	rm -f $(OBJ_PATH)/$(MODULE)
