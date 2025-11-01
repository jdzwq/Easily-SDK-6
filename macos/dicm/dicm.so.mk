#-----------------------------------------------------------------------------
# begin GNU MAKE file
# making order:
# 1. make -f dicm.so.mk test --if need to creating some directory or file-list
# 2. make -f dicm.so.mk clean
# 3. make -f dicm.so.mk
# 4. make -f dicm.so.mk install
#-----------------------------------------------------------------------------
CC = clang
CFLAGS = -g -Wall -fPIC -D _DEBUG

MODULE = dicm
ARCH = aarch64
VER = 6
OUT_PATH = ~/工程/Easily-app-6/macos/sbin
LIB_PATH = /usr/local/lib

INC_PATH = ../../include
SRC_PATH = ../../dicm
OUT_PATH = ../../../Easily-app-6/macos/sbin/api
OBJ_PATH = ~/工程/Easily-temp/macos/$(MODULE)/$(ARCH)

TARGET = lib$(MODULE).so.$(VER)
LINKIT = lib$(MODULE).so

LIBS = -L $(LIB_PATH) -lxdk -lxdl
DIRS = $(wildcard $(SRC_PATH)/*.c)
SRCS = $(notdir $(DIRS))
COBS = $(patsubst %.c, %.o, $(SRCS))
OBJS = $(addprefix $(OBJ_PATH)/,$(COBS))

$(OBJ_PATH)/%.o : $(SRC_PATH)/%.c
	$(CC) $(CFLAGS) -c $< -o $@ -I $(INC_PATH) 

all : $(OBJS)
	rm -f $@
	$(CC) -shared -fPIC -pthread -o $(OUT_PATH)/$(TARGET) $(OBJS) $(LIBS)
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
	if ! test -d $(OUT_PATH)/api; then \
	sudo mkdir -p $(OUT_PATH)/api; \
	fi
	if ! test -d $(LIB_PATH); then \
	sudo mkdir $(LIB_PATH); \
	fi

	sudo cp -f $(OUT_PATH)/$(TARGET) $(OUT_PATH)/api;
	sudo chmod 755 $(OUT_PATH)/api/$(TARGET);
	sudo rm -f $(LIB_PATH)/$(LINKIT);
	sudo ln -s $(OUT_PATH)/api/$(TARGET) $(LIB_PATH)/$(LINKIT);

uninstall:
	sudo rm -r $(LIB_PATH)/$(LINKIT);
	sudo rm -f $(OUT_PATH)/api/$(TARGET)
	
.PHONY : clean
clean:
	rm -f $(OBJS)
#-----------------------------------------------------------------------------
# end GNU MAKE file
#-----------------------------------------------------------------------------