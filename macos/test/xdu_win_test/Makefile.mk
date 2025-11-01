#-----------------------------------------------------------------------------
# begin GNU MAKE file
# making order:
# 1. make -f Makefile.mk test --if need to creating some directory or file-list
# 2. make -f Makefile.mk clean
# 3. make -f Makefile.mk
# 4. make -f Makefile.mk install
#-----------------------------------------------------------------------------
CC = clang
CFLAGS = -g -Wall -D _DEBUG

MODULE = xdu_win_test
ARCH = aarch64

LIB_PATH = /usr/local/lib

XDU_PATH = ~/工程/Easily-sdk-6/xdu
INC_PATH = ~/工程/Easily-sdk-6/include
SRC_PATH = ~/工程/Easily-sdk-6/test/xdu_win_test
OBJ_PATH = ~/工程/Easily-temp/macos/$(MODULE)/$(ARCH)
OUT_PATH = ~/工程/Easily-app-6/macos/bin

DIRS = $(wildcard $(SRC_PATH)/*.cc)
SRCS = $(notdir $(DIRS))
COBS = $(patsubst %.cc, %.o, $(SRCS))
OBJS = $(addprefix $(OBJ_PATH)/,$(COBS))

$(OBJ_PATH)%.o : $(SRC_PATH)/%.cc
	$(CC) $(CFLAGS) -c $< -o $@ -I $(INC_PATH) -I $(XDU_PATH)

all : $(OBJS)
	rm -f $@
	$(CC) -o $(OBJ_PATH)/$(MODULE) $(OBJS) -L $(LIB_PATH) -lxdk -lxdg -lxdu \
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
	sudo mkdir $(OUT_PATH); \
	fi

	sudo cp -f $(OBJ_PATH)/$(MODULE) $(OUT_PATH);
	sudo chmod +x $(OUT_PATH)/$(MODULE);

uninstall:
	sudo rm -f $(OUT_PATH)/$(MODULE)
	
.PHONY : clean
clean:
	rm -f $(OBJS)
	rm -f $(OBJ_PATH)/$(MODULE)
#-----------------------------------------------------------------------------
# end GNU MAKE file
#-----------------------------------------------------------------------------
